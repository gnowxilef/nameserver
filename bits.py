"""
Functions to extract and put data into integers. Finer grained than struct
"""

def extractBits(bitlen, number):
  """
  Extract Bits from a number. Like struct, but smaller.
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
  """
  if len(bitlen.split()) != len(numbers):
    raise Exception("len(numbers) must equal len(bitlen.split())")

  number = 0
  number |= numbers[0]
  i = 1
  for bit in bitlen.split()[1:]:
    number <<= int(bit)
    number |= numbers[i]
    i += 1
  return number
