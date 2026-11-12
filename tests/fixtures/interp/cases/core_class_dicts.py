class Base(object):
    alpha = 1
    beta = 2

    def method(self):
        return self.alpha


class Child(Base):
    gamma = 3
    delta = 4


class Slotted(object):
    __slots__ = ('x', 'y')
    zeta = 5


class Classic:
    one = 1
    two = 2


class Many(object):
    a0 = 0; a1 = 1; a2 = 2; a3 = 3; a4 = 4; a5 = 5; a6 = 6; a7 = 7; a8 = 8; a9 = 9


instance = Child()
instance.first = 1
instance.second = 2
instance.third = 3

slotted = Slotted()
slotted.x = 10

RESULT = (
    list(Base.__dict__),
    list(Child.__dict__),
    list(Slotted.__dict__),
    list(Classic.__dict__),
    list(Many.__dict__),
    list(vars(instance)),
    slotted.x,
    hasattr(slotted, 'y'),
    Child.__mro__ == (Child, Base, object),
    Child().method(),
)
