"""
Functions to extract and put data into integers. Finer grained than struct

>>> extractBits('4 4 4', packBits('4 4 4', 10, 5, 3))
[10, 5, 3]

>>> packBits('4 4 4 5', *extractBits('4 4 4 5', 1492))
1492

>>> packBits('3 2 1 4 5', *extractBits('3 2 1 4 5', 1492))
1492

>>> packBits('1 1 1 1 1 1 4 5 1 6 1', *extractBits('1 1 1 1 1 1 4 5 1 6 1', 1492))
1492
"""
def extractBits(bitlen, number):
  """
  Extract Bits from a number. Like struct, but smaller.

  >>> extractBits('1 2 3 4 5', 0b101001000100001)
  [1, 1, 1, 1, 1]

  >>> extractBits('4 4 4', 0b101000111100)
  [10, 3, 12]

  """
  totalBits = 0
  for bit in bitlen.split():
    totalBits += int(bit)

  currentBits = 0
  extracted = []
  for bit in bitlen.split():
    currentBits += int(bit)
    shifted = number >> totalBits - currentBits
    actual = shifted & ~(-1 << int(bit)) 
    extracted.append(actual)
  return extracted

def packBits(bitlen, *numbers):
  """
  Pack bits into a number

  >>> packBits('1 2 3 4 5', 1, 1, 1, 1, 1)
  21025

  >>> packBits('4 4 4', 10, 3, 12)
  2620
  """
  number = 0
  number |= numbers[0]
  i = 1
  for bit in bitlen.split()[1:]:
    number <<= int(bit)
    number |= numbers[i]
    i += 1
  return number

if __name__ == "__main__":
  import doctest
  doctest.testmod()
