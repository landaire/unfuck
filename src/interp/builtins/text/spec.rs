//! The format specification mini-language,
//! `[[fill]align][sign][#][0][width][,][.precision][type]`, and the text
//! layout of strings and numbers that `format()` and `%` share.

use crate::interp::builtins::text::chars::CodeUnit;

/// Where padding goes when a field is narrower than its width.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Align {
    Left,
    Right,
    Center,
    /// Padding between the sign (and radix prefix) and the digits.
    AfterSign,
}

impl Align {
    fn from_unit(unit: u32) -> Option<Self> {
        match char::from_u32(unit)? {
            '<' => Some(Self::Left),
            '>' => Some(Self::Right),
            '^' => Some(Self::Center),
            '=' => Some(Self::AfterSign),
            _ => None,
        }
    }
}

/// The sign option of a spec.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Sign {
    /// `-`: only negative numbers show a sign.
    Minus,
    /// `+`: every number shows a sign.
    Plus,
    /// ` `: non-negative numbers show a space.
    Space,
}

impl Sign {
    fn from_unit(unit: u32) -> Option<Self> {
        match char::from_u32(unit)? {
            '-' => Some(Self::Minus),
            '+' => Some(Self::Plus),
            ' ' => Some(Self::Space),
            _ => None,
        }
    }
}

/// A parsed spec over the code units of the spec string.
#[derive(Clone, Debug)]
pub(crate) struct FormatSpec<T> {
    pub fill: Option<T>,
    pub align: Option<Align>,
    pub sign: Option<Sign>,
    pub alternate: bool,

    pub width: Option<i64>,
    pub thousands: bool,
    pub precision: Option<i64>,

    /// The presentation type, as written.
    pub kind: Option<T>,
}

/// A spec that the mini-language rejects before any type applies it.
#[derive(Debug, thiserror::Error)]
pub(crate) enum SpecError {
    #[error("Too many decimal digits in format string")]
    TooManyDigits,
    #[error("Format specifier missing precision")]
    MissingPrecision,
    #[error("Invalid conversion specification")]
    InvalidConversion,
    /// `,` with a presentation type that does not group digits.
    #[error("Cannot specify ',' with a non-decimal type")]
    ThousandsWith { kind: u32 },
}

impl<T: CodeUnit> FormatSpec<T> {
    /// Parses `spec`. `default_kind` is the presentation type the
    /// receiver uses when the spec names none; it decides whether `,` is
    /// allowed.
    pub fn parse(spec: &[T], default_kind: Option<u8>) -> Result<Self, SpecError> {
        let mut parsed = Self { fill: None, align: None, sign: None, alternate: false, width: None, thousands: false, precision: None, kind: None };
        let mut position = 0;

        let second_align = spec.get(1).and_then(|unit| Align::from_unit((*unit).into()));
        let first_align = spec.first().and_then(|unit| Align::from_unit((*unit).into()));
        if let Some(align) = second_align {
            parsed.fill = Some(spec[0]);
            parsed.align = Some(align);
            position = 2;
        } else if let Some(align) = first_align {
            parsed.align = Some(align);
            position = 1;
        }

        if let Some(sign) = spec.get(position).and_then(|unit| Sign::from_unit((*unit).into())) {
            parsed.sign = Some(sign);
            position += 1;
        }

        if unit_at(spec, position, b'#') {
            parsed.alternate = true;
            position += 1;
        }

        // A leading zero asks for zero padding after the sign, unless the
        // fill or alignment was given explicitly.
        if unit_at(spec, position, b'0') {
            parsed.fill.get_or_insert(T::from_ascii(b'0'));
            parsed.align.get_or_insert(Align::AfterSign);
            position += 1;
        }

        parsed.width = read_number(spec, &mut position)?;

        if unit_at(spec, position, b',') {
            parsed.thousands = true;
            position += 1;
        }

        if unit_at(spec, position, b'.') {
            position += 1;
            let Some(precision) = read_number(spec, &mut position)? else {
                return Err(SpecError::MissingPrecision);
            };
            parsed.precision = Some(precision);
        }

        match &spec[position..] {
            [] => {}
            [kind] => parsed.kind = Some(*kind),
            _ => return Err(SpecError::InvalidConversion),
        }

        if parsed.thousands {
            let kind = parsed.kind.map(Into::into).or(default_kind.map(u32::from));
            let groups = match kind.and_then(char::from_u32) {
                None => true,
                Some(kind) => "defgEG%F".contains(kind),
            };
            if !groups {
                return Err(SpecError::ThousandsWith { kind: kind.unwrap_or_default() });
            }
        }

        Ok(parsed)
    }

    /// The presentation type, or `default` when none was given.
    pub fn kind_or(&self, default: u8) -> u32 {
        self.kind.map_or(u32::from(default), Into::into)
    }

    pub fn fill_or_space(&self) -> T {
        self.fill.unwrap_or(T::from_ascii(b' '))
    }
}

fn unit_at<T: CodeUnit>(spec: &[T], position: usize, byte: u8) -> bool {
    spec.get(position).is_some_and(|unit| (*unit).into() == u32::from(byte))
}

/// The decimal number starting at `position`, or `None` when no digit is
/// there.
fn read_number<T: CodeUnit>(spec: &[T], position: &mut usize) -> Result<Option<i64>, SpecError> {
    let start = *position;
    let mut value: i64 = 0;
    while let Some(digit) = spec.get(*position).and_then(|unit| decimal_digit(*unit)) {
        value = value.checked_mul(10).and_then(|value| value.checked_add(i64::from(digit))).ok_or(SpecError::TooManyDigits)?;
        *position += 1;
    }

    Ok((*position > start).then_some(value))
}

/// The value of a decimal digit unit. A `unicode` spec accepts any
/// Unicode decimal digit.
pub(crate) fn decimal_digit<T: CodeUnit>(unit: T) -> Option<u8> {
    let code: u32 = unit.into();
    if T::UNICODE {
        let code = u16::try_from(code).ok()?;
        return crate::interp::builtins::text::chars::decimal_value(code);
    }

    (u32::from(b'0')..=u32::from(b'9')).contains(&code).then(|| (code - u32::from(b'0')) as u8)
}

/// Pads `body` to `width` units with `fill` on the side(s) `align` names.
/// `split` is where `Align::AfterSign` inserts its padding.
pub(crate) fn pad<T: Copy>(body: Vec<T>, width: i64, align: Align, fill: T, split: usize) -> Vec<T> {
    let length = body.len() as i64;
    if width <= length {
        return body;
    }

    let padding = (width - length) as usize;
    let (before, after) = match align {
        Align::Left => (0, padding),
        Align::Right => (padding, 0),
        Align::Center => (padding / 2, padding - padding / 2),
        Align::AfterSign => {
            let mut padded = Vec::with_capacity(body.len() + padding);
            padded.extend_from_slice(&body[..split]);
            padded.extend(std::iter::repeat_n(fill, padding));
            padded.extend_from_slice(&body[split..]);
            return padded;
        }
    };

    let mut padded = Vec::with_capacity(body.len() + padding);
    padded.extend(std::iter::repeat_n(fill, before));
    padded.extend(body);
    padded.extend(std::iter::repeat_n(fill, after));

    padded
}

/// A number rendered for a spec, before signs, grouping, and padding.
#[derive(Clone, Debug)]
pub(crate) struct NumberText {
    pub negative: bool,
    /// Radix prefix such as `0x`, kept left of zero padding.
    pub prefix: &'static [u8],
    /// The integer digits that grouping and zero padding apply to; empty
    /// for text such as `inf` that is not made of digits.
    pub digits: Vec<u8>,
    /// Everything right of the integer digits.
    pub tail: Vec<u8>,
}

impl NumberText {
    /// Splits rendered magnitude text at the end of its leading digits.
    pub fn from_magnitude(negative: bool, prefix: &'static [u8], text: &[u8]) -> Self {
        let split = text.iter().position(|byte| !byte.is_ascii_digit()).unwrap_or(text.len());

        Self { negative, prefix, digits: text[..split].to_vec(), tail: text[split..].to_vec() }
    }

    /// The sign shown for this number under `sign`.
    pub fn sign_text(&self, sign: Option<Sign>) -> &'static [u8] {
        match (self.negative, sign) {
            (true, _) => b"-",
            (false, Some(Sign::Plus)) => b"+",
            (false, Some(Sign::Space)) => b" ",
            (false, _) => b"",
        }
    }

    /// Lays the number out: sign, prefix, grouped digits, tail. With `0`
    /// fill after the sign, the zeros become part of the digits and are
    /// grouped with them.
    pub fn layout(&self, spec: &FormatSpec<u8>, sign: Option<Sign>, width: i64, align: Align) -> Vec<u8> {
        let sign_text = self.sign_text(sign);
        let fill = spec.fill_or_space();
        let lead = sign_text.len() + self.prefix.len();

        let digit_width = if align == Align::AfterSign && fill == b'0' && !self.digits.is_empty() { width - (lead + self.tail.len()) as i64 } else { 0 };
        let digits = group_digits(&self.digits, spec.thousands, digit_width);

        let mut body = Vec::with_capacity(lead + digits.len() + self.tail.len());
        body.extend_from_slice(sign_text);
        body.extend_from_slice(self.prefix);
        body.extend_from_slice(&digits);
        body.extend_from_slice(&self.tail);

        pad(body, width, align, fill, lead)
    }
}

/// `digits` with leading zeros added until the result is at least
/// `min_width` long, and a comma between groups of three when
/// `thousands`. A result never starts with a comma.
pub(crate) fn group_digits(digits: &[u8], thousands: bool, min_width: i64) -> Vec<u8> {
    let grouped_length = |count: usize| if thousands && count > 0 { count + (count - 1) / 3 } else { count };

    let mut count = digits.len();
    let wanted = usize::try_from(min_width).unwrap_or(0);
    if grouped_length(count) < wanted {
        // Each four output units hold three digits; start just below the
        // answer and step up.
        count = count.max(if thousands { (wanted * 3 / 4).saturating_sub(1) } else { wanted });
        while grouped_length(count) < wanted {
            count += 1;
        }
    }

    let zeros = count - digits.len();
    let padded = std::iter::repeat_n(b'0', zeros).chain(digits.iter().copied());
    if !thousands {
        return padded.collect();
    }

    let mut grouped = Vec::with_capacity(grouped_length(count));
    for (index, digit) in padded.enumerate() {
        if index > 0 && (count - index) % 3 == 0 {
            grouped.push(b',');
        }
        grouped.push(digit);
    }

    grouped
}

/// The layout of a float's digits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FloatForm {
    /// `f`: a fixed number of fractional digits.
    Fixed,
    /// `e`: one integer digit and an exponent.
    Exponent,
    /// `g`: significant digits, positional for moderate exponents.
    General,
    /// A spec without a type: like `g`, but positional output keeps a
    /// fractional digit and the exponent form starts one integer digit
    /// earlier.
    Plain,
}

/// Fractional digits beyond which every finite double's expansion is
/// zero.
const MAX_FRACTION_DIGITS: usize = 1080;

/// Significant digits beyond which every finite double's expansion is
/// zero.
const MAX_SIGNIFICANT_DIGITS: usize = 800;

/// An upper bound on the length of `render_float` text, for checking
/// allocations before rendering.
pub(crate) fn float_length_bound(form: FloatForm, precision: usize, alternate: bool) -> i64 {
    let precision = precision as i64;
    match form {
        FloatForm::Fixed => precision + 320,
        FloatForm::Exponent => precision + 10,
        FloatForm::General if alternate => precision + 10,
        FloatForm::General | FloatForm::Plain => precision.min(MAX_SIGNIFICANT_DIGITS as i64) + 330,
    }
}

/// The text of a float's magnitude in `form` with `precision`, and
/// whether a minus sign belongs in front of it. A NaN never has one.
/// `alternate` keeps a decimal point and trailing zeros.
pub(crate) fn render_float(value: f64, form: FloatForm, precision: usize, alternate: bool, upper: bool) -> (bool, String) {
    if value.is_nan() {
        return (false, if upper { "NAN" } else { "nan" }.to_owned());
    }

    let negative = value.is_sign_negative();
    if value.is_infinite() {
        return (negative, if upper { "INF" } else { "inf" }.to_owned());
    }

    let magnitude = value.abs();
    let text = match form {
        FloatForm::Fixed => fixed(magnitude, precision, alternate),
        FloatForm::Exponent => {
            let (mut digits, exponent) = significant_digits(magnitude, precision + 1);
            digits.resize(precision + 1, b'0');
            scientific(&digits, exponent, alternate, true)
        }
        FloatForm::General => general(magnitude, precision.max(1), precision.max(1), alternate, false),
        FloatForm::Plain => general(magnitude, precision.max(1), precision.max(1) - 1, false, true),
    };

    (negative, if upper { text.to_ascii_uppercase() } else { text })
}

fn fixed(magnitude: f64, precision: usize, alternate: bool) -> String {
    let shown = precision.min(MAX_FRACTION_DIGITS);
    let mut text = format!("{magnitude:.shown$}");
    text.extend(std::iter::repeat_n('0', precision - shown));
    if alternate && precision == 0 {
        text.push('.');
    }

    text
}

/// `count` significant decimal digits of a non-negative finite value,
/// rounded half to even, and the exponent of the first:
/// `value = d0.d1d2... * 10^exponent`. Zero has exponent 0. Digits past
/// the exact expansion are left off; they are all zero.
fn significant_digits(magnitude: f64, count: usize) -> (Vec<u8>, i32) {
    if magnitude == 0.0 {
        return (vec![b'0'; count.min(MAX_SIGNIFICANT_DIGITS)], 0);
    }

    let shown = count.min(MAX_SIGNIFICANT_DIGITS);
    let text = format!("{magnitude:.prec$e}", prec = shown - 1);
    let (mantissa, exponent) = text.split_once('e').unwrap_or((&text, "0"));
    let digits = mantissa.bytes().filter(u8::is_ascii_digit).collect();

    (digits, exponent.parse().unwrap_or(0))
}

/// Digit `index` of `digits`, where digits past the end are zeros.
fn digit_at(digits: &[u8], index: usize) -> u8 {
    digits.get(index).copied().unwrap_or(b'0')
}

/// `d.ddde+XX`, with `digits.len()` significant digits. `keep_zeros`
/// keeps trailing fractional zeros; `alternate` keeps the point.
fn scientific(digits: &[u8], exponent: i32, alternate: bool, keep_zeros: bool) -> String {
    let mut fraction: &[u8] = &digits[1..];
    if !keep_zeros {
        let end = fraction.iter().rposition(|digit| *digit != b'0').map_or(0, |last| last + 1);
        fraction = &fraction[..end];
    }

    let mut text = String::with_capacity(digits.len() + 8);
    text.push(char::from(digits[0]));
    if !fraction.is_empty() || alternate {
        text.push('.');
    }
    text.extend(fraction.iter().copied().map(char::from));
    text.push('e');
    text.push(if exponent < 0 { '-' } else { '+' });
    text.push_str(&format!("{:02}", exponent.unsigned_abs()));

    text
}

/// `g`-style text with `significant` digits. Output is positional when
/// the exponent is at least -4 and below `threshold`. `plain` gives
/// positional output a `.0` when it would have no point.
fn general(magnitude: f64, significant: usize, threshold: usize, alternate: bool, plain: bool) -> String {
    let (mut digits, exponent) = significant_digits(magnitude, significant);
    if alternate {
        digits.resize(significant, b'0');
    }

    let positional = exponent >= -4 && i64::from(exponent) < threshold as i64;
    if !positional {
        return scientific(&digits, exponent, alternate, alternate);
    }

    let mut integer = Vec::new();
    let mut fraction = Vec::new();
    if exponent < 0 {
        integer.push(b'0');
        fraction.extend(std::iter::repeat_n(b'0', (-exponent - 1) as usize));
        fraction.extend_from_slice(&digits);
    } else {
        let integer_digits = exponent as usize + 1;
        integer.extend((0..integer_digits).map(|index| digit_at(&digits, index)));
        fraction.extend_from_slice(digits.get(integer_digits..).unwrap_or_default());
    }

    if !alternate {
        let end = fraction.iter().rposition(|digit| *digit != b'0').map_or(0, |last| last + 1);
        fraction.truncate(end);
    }

    let mut text = String::from_utf8(integer).unwrap_or_default();
    if !fraction.is_empty() || alternate {
        text.push('.');
        text.extend(fraction.iter().copied().map(char::from));
    } else if plain {
        text.push_str(".0");
    }

    text
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rendered(value: f64, form: FloatForm, precision: usize, alternate: bool) -> String {
        let (negative, text) = render_float(value, form, precision, alternate, false);

        if negative { format!("-{text}") } else { text }
    }

    #[test]
    fn float_forms() {
        let cases = [
            (1.5, FloatForm::Fixed, 0, false, "2"),
            (2.5, FloatForm::Fixed, 0, false, "2"),
            (1.0, FloatForm::Fixed, 0, true, "1."),
            (1.0, FloatForm::Exponent, 0, true, "1.e+00"),
            (1.125, FloatForm::Exponent, 2, false, "1.12e+00"),
            (1e100, FloatForm::Exponent, 6, false, "1.000000e+100"),
            (1e-5, FloatForm::General, 6, false, "1e-05"),
            (123456.0, FloatForm::General, 6, false, "123456"),
            (1234567.0, FloatForm::General, 6, false, "1.23457e+06"),
            (1.0, FloatForm::General, 6, true, "1.00000"),
            (0.0, FloatForm::General, 6, true, "0.00000"),
            (100.0, FloatForm::General, 3, true, "100."),
            (123.0, FloatForm::General, 0, true, "1.e+02"),
            (1.5, FloatForm::Plain, 0, false, "2e+00"),
            (1.0, FloatForm::Plain, 3, false, "1.0"),
            (1e16, FloatForm::Plain, 20, false, "10000000000000000.0"),
            (1e15, FloatForm::Plain, 12, false, "1e+15"),
            (-0.0, FloatForm::Plain, 12, false, "-0.0"),
            (0.1, FloatForm::General, 20, false, "0.10000000000000000555"),
            (1.5, FloatForm::General, 2_147_483_647, false, "1.5"),
            (5e-324, FloatForm::Plain, 12, false, "4.94065645841e-324"),
            (1e10, FloatForm::Plain, 12, false, "10000000000.0"),
            (1e11, FloatForm::Plain, 12, false, "1e+11"),
            (0.5, FloatForm::Plain, 0, false, "0.5"),
            (55.0, FloatForm::Plain, 2, false, "5.5e+01"),
            (5.0, FloatForm::Plain, 2, false, "5.0"),
        ];

        for (value, form, precision, alternate, expected) in cases {
            assert_eq!(rendered(value, form, precision, alternate), expected, "{value} {form:?} {precision} {alternate}");
        }
    }

    #[test]
    fn grouping_never_starts_with_a_comma() {
        let cases = [(&b"1234567"[..], 12, "0,001,234,567"), (b"1234567", 14, "00,001,234,567"), (b"0", 4, "0,000"), (b"0", 6, "00,000"), (b"12", 8, "0,000,012"), (b"1234", 0, "1,234")];

        for (digits, width, expected) in cases {
            assert_eq!(String::from_utf8(group_digits(digits, true, width)).unwrap(), expected);
        }
    }
}
