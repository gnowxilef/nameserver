def extractBits(bitlen, number):
  totalBits = 0
  for bit in bitlen.split():
    totalBits += int(bit)

  currentBits = 0
  extracted = []
  for bit in bitlen.split():
    currentBits += int(bit)
    shifted = number >> totalBits - currentBits
    actual = shifted & ~(-1 << int(bit)) 
    extracted.push_back(actual)
  return extracted
