use crate::code_graph::{BasicBlockFlags, CodeGraph, EdgeWeight};

use crossbeam::channel::Sender;
use log::{debug, error, trace};
use num_bigint::ToBigInt;

use petgraph::graph::NodeIndex;
use petgraph::visit::{Bfs, EdgeRef};
use petgraph::Direction;

use py27_marshal::{Code, Obj};
use pydis::opcode::py27::{self, Mnemonic};
use pydis::prelude::*;
use std::collections::{BTreeSet, HashMap};

use std::sync::{Arc, Mutex, RwLock};

/// Represents an execution path taken by the VM
#[derive(Debug, Default, Clone)]
pub struct ExecutionPath {
    /// Stack at the end of this path
    pub stack: crate::smallvm::VmStack<AccessTrackingInfo>,
    /// Vars at the end of this path
    pub vars: crate::smallvm::VmVars<AccessTrackingInfo>,
    /// Names at the end of this path
    pub names: crate::smallvm::VmNames<AccessTrackingInfo>,
    /// Globals at the end of this path
    pub globals: crate::smallvm::VmNames<AccessTrackingInfo>,
    /// Names loaded at the end of this path
    pub names_loaded: crate::smallvm::LoadedNames,
    /// Values for each conditional jump along this execution path
    pub condition_results: HashMap<NodeIndex, Option<(EdgeWeight, Vec<AccessTrackingInfo>)>>,
    /// Nodes that have been executed
    pub executed_nodes: BTreeSet<NodeIndex>,
    /// Loops that we're executing in
    pub executing_loop_offsets: Vec<NodeIndex>,
}

/// Information required to track back an instruction that accessed/tainted a var
pub type AccessTrackingInfo = (petgraph::graph::NodeIndex, usize);

/// Performs partial VM execution. This will execute each instruction and record execution
/// paths down conditional branches. If a branch path cannot be determined, this path "ends" and
/// is forked down both directions.
// This function will return all execution paths until they end.
pub(crate) fn perform_partial_execution<
    'a,
    TargetOpcode: 'static + Opcode<Mnemonic = py27::Mnemonic>,
>(
    root: NodeIndex,
    code_graph: &'a RwLock<&'a mut CodeGraph<TargetOpcode>>,
    mut execution_path_lock: Mutex<ExecutionPath>,
    mapped_function_names: &'a Mutex<HashMap<String, String>>,
    code: Arc<Code>,
    scope: &rayon::Scope<'a>,
    completed_paths_sender: &'a Sender<Mutex<ExecutionPath>>,
) {
    trace!("Executing from node index {:?}", root);
    let execution_path: &mut ExecutionPath = execution_path_lock.get_mut().unwrap();
    let debug = !false;
    let debug_stack = false;
    macro_rules! current_node {
        () => {
            code_graph.read().unwrap().graph[root]
        };
    }

    let targets = {
        let graph = code_graph.read().unwrap();
        let mut edges = graph
            .graph
            .edges_directed(root, Direction::Outgoing)
            .collect::<Vec<_>>();

        // Sort these edges so that we serialize the non-jump path first
        edges.sort_by(|a, b| a.weight().cmp(b.weight()));
        edges
            .iter()
            .map(|edge| (edge.weight().clone(), edge.target(), edge.id()))
            .collect::<Vec<_>>()
    };

    execution_path.executed_nodes.insert(root);

    let instrs: Vec<_> = current_node!()
        .instrs
        .iter()
        .map(|instr| instr.unwrap())
        .enumerate()
        .collect();

    for (ins_idx, instr) in instrs {
        // We handle jumps
        if instr.opcode.mnemonic() == Mnemonic::RETURN_VALUE {
            completed_paths_sender
                .send(execution_path_lock)
                .expect("failed to send the completed execution path");
            return;
        }

        if debug {
            trace!(
                "DEAD CODE REMOVAL INSTR: {:?}, KEY: {:?}",
                instr,
                (root, ins_idx)
            );
        }

        // We've reached a conditional jump. We either know the condition, or we do not. If we can
        // identify the condition, we will only go down the branch taken. Otherwise we will take both branches.
        if instr.opcode.is_conditional_jump() {
            let (tos_ref, modifying_instructions) = execution_path.stack.last().unwrap();
            let mut tos = tos_ref.as_ref();
            if debug_stack {
                trace!("TOS: {:?}", tos);
            }

            // Check if this node is downgraph from something that looks like a loop
            let first_loop = execution_path.executing_loop_offsets.first();

            // If we had a parent loop node, let's figure out if our operands
            // change in this loop
            //
            // TODO: Maybe handle nested loops?
            if let Some(parent_loop) = first_loop {
                let fast_operands = modifying_instructions
                    .0
                    .lock()
                    .unwrap()
                    .iter()
                    .filter_map(|(nx, ix)| {
                        let instr = code_graph.read().unwrap().graph[*nx].instrs[*ix].unwrap();
                        if instr.opcode.mnemonic() == Mnemonic::LOAD_FAST {
                            Some(instr.arg.unwrap())
                        } else {
                            None
                        }
                    })
                    .collect::<BTreeSet<_>>();

                // Now check if these operands are modified in any node within the loop that has *not*
                // yet been executed

                let mut bfs = Bfs::new(&code_graph.read().unwrap().graph, *parent_loop);
                while let Some(nx) = bfs.next(&code_graph.read().unwrap().graph) {
                    for instr in &code_graph.read().unwrap().graph[nx].instrs {
                        let instr = instr.unwrap();

                        // Check if this instruction clobbers one of the vars we
                        // use. This happens if it's a STORE_FAST with a matching
                        // index AND the node has not been executed by this execution
                        // path.
                        if instr.opcode.mnemonic() == Mnemonic::STORE_FAST
                            && fast_operands.contains(&instr.arg.unwrap())
                            && !execution_path.executed_nodes.contains(&nx)
                        {
                            // we have a match. this means that this loop modifies
                            // our condition. we shouldn't respect this TOS value
                            tos = None;
                            break;
                        }
                    }
                }
            }

            // we know where this jump should take us
            if let Some(tos) = tos {
                // if *code.filename == "26949592413111478" && *code.name == "50857798689625" {
                //     panic!("{:?}", tos);
                // }
                // this flag is really only useful for debugging
                code_graph.write().unwrap().graph[root].flags |=
                    BasicBlockFlags::CONSTEXPR_CONDITION;

                if debug_stack {
                    trace!("{:#?}", modifying_instructions);
                }
                let modifying_instructions = modifying_instructions.clone();

                if debug {
                    trace!("CONDITION TOS:");
                    trace!("{:#?}", code_graph.read().unwrap().graph[root].start_offset);
                    trace!("{:?}", tos);
                    trace!("{:?}", instr);

                    if debug_stack {
                        trace!("{:#?}", modifying_instructions);
                    }
                    trace!("END CONDITION TOS");
                }

                macro_rules! extract_truthy_value {
                    ($value:expr) => {
                        match $value {
                            Some(Obj::Bool(result)) => result,
                            Some(Obj::Long(result)) => *result != 0.to_bigint().unwrap(),
                            Some(Obj::Float(result)) => result != 0.0,
                            Some(Obj::Set(result_lock)) => {
                                let result = result_lock.read().unwrap();
                                !result.is_empty()
                            }
                            Some(Obj::List(result_lock)) => {
                                let result = result_lock.read().unwrap();
                                !result.is_empty()
                            }
                            Some(Obj::Tuple(result)) => !result.is_empty(),
                            Some(Obj::String(result)) => !result.is_empty(),
                            Some(Obj::None) => false,
                            other => {
                                panic!("unexpected TOS type for condition: {:?}", other);
                            }
                        }
                    };
                }
                let target_weight = match instr.opcode.mnemonic() {
                    Mnemonic::POP_JUMP_IF_FALSE => {
                        let tos = execution_path.stack.pop().unwrap().0;
                        if !extract_truthy_value!(tos) {
                            EdgeWeight::Jump
                        } else {
                            EdgeWeight::NonJump
                        }
                    }
                    Mnemonic::POP_JUMP_IF_TRUE => {
                        let tos = execution_path.stack.pop().unwrap().0;
                        if extract_truthy_value!(tos) {
                            EdgeWeight::Jump
                        } else {
                            EdgeWeight::NonJump
                        }
                    }
                    Mnemonic::JUMP_IF_TRUE_OR_POP => {
                        if extract_truthy_value!(Some(tos.clone())) {
                            EdgeWeight::Jump
                        } else {
                            execution_path.stack.pop();
                            EdgeWeight::NonJump
                        }
                    }
                    Mnemonic::JUMP_IF_FALSE_OR_POP => {
                        if !extract_truthy_value!(Some(tos.clone())) {
                            EdgeWeight::Jump
                        } else {
                            execution_path.stack.pop();
                            EdgeWeight::NonJump
                        }
                    }
                    other => panic!("did not expect opcode {:?} with static result", other),
                };
                if debug {
                    trace!("{:?}", instr);
                    if debug_stack {
                        trace!("stack after: {:#?}", execution_path.stack);
                    }
                }

                let target = targets
                    .iter()
                    .find_map(|(weight, idx, _edge)| {
                        if *weight == target_weight {
                            Some(*idx)
                        } else {
                            None
                        }
                    })
                    .unwrap();

                modifying_instructions.push((root, ins_idx));
                execution_path.condition_results.insert(
                    root,
                    Some((
                        target_weight,
                        modifying_instructions.0.lock().unwrap().clone(),
                    )),
                );

                trace!(
                    "dead code analysis on: {:?}",
                    code_graph.read().unwrap().graph[target]
                );

                scope.spawn(move |s| {
                    perform_partial_execution(
                        target,
                        code_graph,
                        execution_path_lock,
                        &mapped_function_names,
                        Arc::clone(&code),
                        s,
                        &completed_paths_sender,
                    );
                });
                return;
            }
        }

        // We failed to identify the conditional jump. We will go down both branches.

        if debug {
            trace!("{:?}", instr);
        }

        // If this next instruction is _not_ a jump, we need to evaluate it
        if !instr.opcode.is_jump() {
            // if this is a "STORE_NAME" instruction let's see if this data originates
            // at a MAKE_FUNCTION
            if instr.opcode.mnemonic() == Mnemonic::STORE_NAME {
                // TOS _may_ be a function object.
                if let Some((_tos, accessing_instructions)) = execution_path.stack.last() {
                    trace!("Found a STORE_NAME");
                    // this is the data we're storing. where does it originate?
                    let was_make_function =
                        accessing_instructions.0.lock().unwrap().iter().rev().any(
                            |(source_node, idx)| {
                                let source_instruction =
                                    &code_graph.read().unwrap().graph[*source_node].instrs[*idx]
                                        .unwrap();
                                source_instruction.opcode.mnemonic() == Mnemonic::MAKE_FUNCTION
                            },
                        );

                    // Does the data originate from a MAKE_FUNCTION?
                    if was_make_function {
                        trace!("A MAKE_FUNCTION preceded the STORE_NAME");
                        let (const_origination_node, const_idx) =
                            accessing_instructions.0.lock().unwrap()[0].clone();

                        let const_instr = &code_graph.read().unwrap().graph[const_origination_node]
                            .instrs[const_idx];
                        let const_instr = const_instr.unwrap();

                        trace!("{:#?}", accessing_instructions.0.lock().unwrap());
                        trace!("{:#?}", instr);
                        for (node, instr) in &*accessing_instructions.0.lock().unwrap() {
                            let const_instr =
                                &code_graph.read().unwrap().graph[*node].instrs[*instr];
                            trace!("{:#?}", const_instr);
                        }

                        if const_instr.opcode.mnemonic() == Mnemonic::LOAD_CONST {
                            let const_idx = const_instr.arg.unwrap() as usize;

                            if let Obj::Code(code) = &code.consts[const_idx] {
                                let key = format!(
                                    "{}_{}",
                                    code.filename.to_string(),
                                    code.name.to_string()
                                );
                                // TODO: figure out why this Arc::clone is needed and we cannot
                                // just take a reference...
                                if (instr.arg.unwrap() as usize) < code.names.len() {
                                    let name = Arc::clone(&code.names[instr.arg.unwrap() as usize]);
                                    mapped_function_names
                                        .lock()
                                        .unwrap()
                                        .insert(key, name.to_string());
                                }
                            } else {
                                error!("could not trace MAKE_FUNCTION back to a LOAD_CONST -- first instruction in access tracking is {:?}. this is likely a bug", const_instr.opcode.mnemonic());
                            }
                        } else {
                            error!(
                                "mapped function is supposed to be a code object. got {:?}",
                                code.consts[const_idx].typ()
                            );
                        };
                    }
                }
            }

            // RAISE_VARARGS is tricky because I'm not yet sure where it should land us -- we don't evaluate these
            if instr.opcode.mnemonic() == Mnemonic::RAISE_VARARGS {
                if debug {
                    trace!("skipping -- it's RAISE_VARARGS");
                }
                continue;
            }

            let names_loaded = Arc::clone(&execution_path.names_loaded);
            // Execute the instruction
            if let Err(e) = crate::smallvm::execute_instruction(
                &*instr,
                Arc::clone(&code),
                &mut execution_path.stack,
                &mut execution_path.vars,
                &mut execution_path.names,
                &mut execution_path.globals,
                Arc::clone(&execution_path.names_loaded),
                |function, _args, _kwargs| {
                    // we dont execute functions here
                    if function.is_some() {
                        debug!("need to implement call_function: {:?}", function);
                    } else if let Some(name) = names_loaded.lock().unwrap().last() {
                        if let Ok(function_name) = std::str::from_utf8(&*name.as_slice()) {
                            debug!("maybe can implement call_function: {:?}", function_name);
                        }
                    }
                    None
                },
                (root, ins_idx),
            ) {
                // We got an error. Let's end this trace -- we can not confidently identify further stack values
                error!("Encountered error executing instruction: {:?}", e);
                let _last_instr = current_node!().instrs.last().unwrap().unwrap();

                completed_paths_sender
                    .send(execution_path_lock)
                    .expect("failed to send the completed execution path");
                return;
            }
        }

        if debug_stack {
            trace!(
                "out of instructions -- stack after: {:#?}",
                execution_path.stack
            );
        }
    }

    if debug {
        trace!("going to other nodes");
    }

    execution_path.condition_results.insert(root, None);

    // This path is complete. We are about to fork this path down a branch
    // whose true execution path is unknown
    completed_paths_sender
        .send(Mutex::new(execution_path.clone()))
        .expect("failed to send the completed execution path");

    // We reached the last instruction in this node -- go on to the next
    // We don't know which branch to take
    for (weight, target, _edge) in targets {
        if debug {
            trace!(
                "target: {}",
                code_graph.read().unwrap().graph[target].start_offset
            );
        }

        let mut last_instr_was_for_iter = false;
        if let Some(last_instr) = code_graph.read().unwrap().graph[root]
            .instrs
            .last()
            .map(|instr| instr.unwrap())
        {
            // we never follow exception paths
            if last_instr.opcode.mnemonic() == Mnemonic::SETUP_EXCEPT && weight == EdgeWeight::Jump
            {
                if debug {
                    trace!("skipping -- it's SETUP_EXCEPT");
                }
                continue;
            }

            // Loops we have to handle special
            if matches!(
                last_instr.opcode.mnemonic(),
                Mnemonic::FOR_ITER | Mnemonic::SETUP_LOOP
            ) && weight == EdgeWeight::NonJump
            {
                last_instr_was_for_iter = true;
                execution_path.executing_loop_offsets.push(root);

                if debug {
                    trace!("skipping -- it's for_iter");
                }
                // continue;
            }
        }

        // Make sure that we're not being cyclic
        // let is_cyclic = code_graph
        //     .graph
        //     .edges_directed(target, Direction::Outgoing)
        //     .any(|edge| edge.target() == root);
        // if is_cyclic {
        //     if debug {
        //         trace!("skipping -- root is downgraph from target");
        //     }
        //     continue;
        // }

        if debug_stack {
            trace!("STACK BEFORE {:?} {:#?}", root, execution_path.stack);
        }

        // Check if we're looping again. If so, we don't take this path
        if execution_path.executed_nodes.contains(&target) {
            trace!("skipping target node -- it's been executed");
            continue;
        }

        let mut execution_path = execution_path.clone();
        // TODO: this should be fixed once we properly support objects
        if last_instr_was_for_iter && weight == EdgeWeight::NonJump {
            execution_path
                .stack
                .push((None, crate::smallvm::InstructionTracker::new()));
        }

        let target_code = Arc::clone(&code);
        scope.spawn(move |s| {
            perform_partial_execution(
                target,
                code_graph,
                Mutex::new(execution_path),
                &mapped_function_names,
                target_code,
                s,
                &completed_paths_sender,
            );
        });
    }
}
