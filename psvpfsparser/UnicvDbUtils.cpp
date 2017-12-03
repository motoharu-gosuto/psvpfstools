#include "UnicvDbUtils.h"

#include "UnicvDbTypes.h"

uint32_t binTreeNumMaxAvail(uint32_t signatureSize, uint32_t pageSize)
{
  return (pageSize - sizeof(sig_tbl_header_t)) / signatureSize;
}

uint32_t binTreeSize(uint32_t signatureSize, uint32_t binTreeNumMaxAvail)
{
  return binTreeNumMaxAvail * signatureSize + sizeof(sig_tbl_header_t);
}