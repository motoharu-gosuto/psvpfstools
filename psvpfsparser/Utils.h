#pragma once

#include <cstdint>
#include <vector>
#include <set>
#include <fstream>

#include <boost/filesystem.hpp>
#include <boost/range/adaptor/reversed.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/algorithm/string.hpp>

bool isZeroVector(const std::vector<std::uint8_t>& data);

template<typename T>
bool isZeroVector(T begin, T end)
{
   for(T it = begin; it != end; ++it)
   {
      if((*it) != 0)
         return false;
   }
   return true;
}

int string_to_byte_array(std::string str, std::uint32_t nBytes, unsigned char* dest);

std::string byte_array_to_string(const unsigned char* source, int nBytes);

int print_bytes(const unsigned char* bytes, int length);

void getFileListNoPfs(boost::filesystem::path root_path, std::set<boost::filesystem::path>& files, std::set<boost::filesystem::path>& directories);

//this can be linked only to existing file!
struct sce_junction
{
private:
   boost::filesystem::path m_value; //virtual path in files.db
   mutable boost::filesystem::path m_real; //real path in file system

public:
   sce_junction(boost::filesystem::path value);

   sce_junction(const sce_junction& other);

public:
   bool is_equal(boost::filesystem::path p) const;

   bool is_equal(const sce_junction& other) const;

public:
   bool operator<(const sce_junction& other);

   bool operator<(const sce_junction& other) const;

public:
   void link_to_real(const sce_junction& p) const;

public:
   //get size of real file linked with this junction
   boost::uintmax_t file_size() const;

   //open real file linked with this junction
   bool open(std::ifstream& in) const;

   //create empty directory in destination root using path from this junction
   bool create_empty_directory(boost::filesystem::path source_root, boost::filesystem::path destination_root) const;

   //create empty file in destination root using path from this junction
   //leaves stream opened for other operations like write
   bool create_empty_file(boost::filesystem::path source_root, boost::filesystem::path destination_root, std::ofstream& outputStream) const;

   //create empty file in destination root using path from this junction
   bool create_empty_file(boost::filesystem::path source_root, boost::filesystem::path destination_root) const;

   //copy file in destination root using path from this junction
   bool copy_existing_file(boost::filesystem::path source_root, boost::filesystem::path destination_root) const;

   //copy file with specific size in destination root using path from this junction
   bool copy_existing_file(boost::filesystem::path source_root, boost::filesystem::path destination_root, std::uintmax_t size) const;

public:
   //this operator should only be used for printing to console!
   friend std::ostream& operator<<(std::ostream& os, const sce_junction& p);  
};