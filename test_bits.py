from bits import *
import pytest

class TestBoth:
  def test_extract_pack(self):
    assert extractBits('4 4 4', packBits('4 4 4', 10, 5, 3)) == [10, 5, 3]

  def test_pack_extract_one(self):
    assert packBits('4 4 4 5', *extractBits('4 4 4 5', 1492)) == 1492

  def test_pack_extract_two(self):
    assert packBits('3 2 1 4 5', *extractBits('3 2 1 4 5', 1492)) == 1492

  def test_pack_extract_three(self):
    assert packBits('1 1 1 1 1 1 4 5 1 6 1', 
                    *extractBits('1 1 1 1 1 1 4 5 1 6 1', 1492)) == 1492

class TestExtractBits:
  def test_one(self):
    assert extractBits('1 2 3 4 5', int('101001000100001', 2)) == [1, 1, 1, 1, 1]

  def test_two(self):
    assert extractBits('4 4 4', int('101000111100', 2)) == [10, 3, 12]
 
class TestPackBits:
  def test_one(self):
    assert packBits('1 2 3 4 5', 1, 1, 1, 1, 1) == int('101001000100001', 2)

  def test_two(self):
    assert packBits('4 4 4', 10, 3, 12) == 2620

  def test_too_few(self):
    with pytest.raises(Exception):
      packBits('4 4 4', 10, 3)

  def test_too_many(self):
    with pytest.raises(Exception):
      packBits('4 4 4', 10, 3, 10, 10)


