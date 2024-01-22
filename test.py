from helloi1world import *

def test_add():
    assert add(2,3) == 6

def test_subtract():
    assert subtract(2, 3) == -1

def test_multiply():
    assert multiply(2, 3) == 6

def test_divide():
    assert divide(10,5) == 2

if __name__ == "__main__":
    test_add()
