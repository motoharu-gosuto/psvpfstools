#pragma once

#include <cstdint>

#include <memory>
#include <map>
#include <iostream>
#include <vector>

#include <boost/filesystem.hpp>

#include "IF00DKeyEncryptor.h"
#include "ICryptoOperations.h"

#include "Utils.h"
#include "UnicvDbTypes.h"

class FilesDbParser;
class UnicvDbParser;

class sce_iftbl_base_t;
class icv;

class PfsPageMapper
{
private:
   std::map<std::uint32_t, sce_junction> m_pageMap;
   std::set<sce_junction> m_emptyFiles;

private:
   std::shared_ptr<ICryptoOperations> m_cryptops;
   std::shared_ptr<IF00DKeyEncryptor> m_iF00D;
   std::ostream& m_output;
   unsigned char m_klicensee[0x10];
   boost::filesystem::path m_titleIdPath;

public:
   PfsPageMapper(std::shared_ptr<ICryptoOperations> cryptops, std::shared_ptr<IF00DKeyEncryptor> iF00D, std::ostream& output, const unsigned char* klicensee, boost::filesystem::path titleIdPath);

private:
   std::shared_ptr<sce_junction> brutforce_hashes(const std::unique_ptr<FilesDbParser>& filesDbParser, std::map<sce_junction, std::vector<std::uint8_t>>& fileDatas, const unsigned char* secret, const unsigned char* signature) const;

   int compare_hash_tables(const std::vector<icv>& left, const std::vector<std::shared_ptr<icv> >& right);

   int validate_merkle_trees(const std::unique_ptr<sce_idb_base_t>& idb, const std::uint32_t files_salt, const std::uint16_t img_spec) const;
   int validate_merkle_tree(const std::shared_ptr<sce_iftbl_base_t> ftbl, const std::uint32_t page_idx, const std::uint32_t sig_idx, unsigned char* secret) const;

public:
   int bruteforce_map(const std::unique_ptr<FilesDbParser>& filesDbParser, const std::unique_ptr<UnicvDbParser>& unicvDbParser);

   int load_page_map(boost::filesystem::path filepath, std::map<std::uint32_t, std::string>& pageMap) const;

public:
   const std::map<std::uint32_t, sce_junction>& get_pageMap() const;

   const std::set<sce_junction>& get_emptyFiles() const;
};