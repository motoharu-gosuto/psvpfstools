#include <cstdint>
#include <iomanip>
#include <vector>
#include <string>
#include <iostream>
#include <set>

#include <boost/filesystem.hpp>
#include <boost/range/adaptor/reversed.hpp>
#include <boost/algorithm/string/predicate.hpp>

#include "Utils.h"

bool isZeroVector(const std::vector<std::uint8_t>& data)
{
   return isZeroVector(data.cbegin(), data.cend());
}

int string_to_byte_array(std::string str, std::uint32_t nBytes, unsigned char* dest)
{
   if(str.length() < nBytes * 2)
      return -1;

   for(std::uint32_t i = 0, j = 0 ; j < nBytes; i = i + 2, j++)
   {
      std::string byteString = str.substr(i, 2);
      unsigned char byte = (unsigned char)strtol(byteString.c_str(), NULL, 16);
      dest[j] = byte;
   }
   return 0;
}

std::string byte_array_to_string(const unsigned char* source, int nBytes)
{
   std::vector<char> result(nBytes * 2 + 1);

   for(int i = 0, j = 0 ; j < nBytes; i = i + 2, j++)
   {
      sprintf(result.data() + i, "%02x", source[j]);
   }

   return std::string(result.data(), nBytes * 2);
}

int print_bytes(const unsigned char* bytes, int length)
{
   for(int i = 0; i < length; i++)
   {
      std::cout << std::hex << std::setfill('0') << std::setw(2) << (0xFF & (int)bytes[i]);
   }
   std::cout << std::endl;
   return 0;
}

//get files recoursively
void getFileListNoPfs(boost::filesystem::path root_path, std::set<boost::filesystem::path>& files, std::set<boost::filesystem::path>& directories)
{
   if (!root_path.empty())
   {
      boost::filesystem::path apk_path(root_path);
      boost::filesystem::recursive_directory_iterator end;

      for (boost::filesystem::recursive_directory_iterator i(apk_path); i != end; ++i)
      {
         const boost::filesystem::path cp = (*i);

         //skip paths that are not included in files.db
         //i.nopush(true) will skip recursion into directory

         //skip pfs directory
         if(cp.filename() == boost::filesystem::path("sce_pfs")) {
            i.no_push(true);
            continue;
         }

         //skip packages
         if(cp == (root_path / boost::filesystem::path("sce_sys") / boost::filesystem::path("package"))) {
            i.no_push(true);
            continue;
         }

         //skip pfs inside sce_sys (for ADDCONT)
         if(boost::ends_with(cp, boost::filesystem::path("sce_sys")) &&
               cp != root_path / boost::filesystem::path("sce_sys") &&
               boost::filesystem::exists(cp / boost::filesystem::path("keystone"))) {
            i.no_push(true);
            continue;
         }

         //add file or directory
         if(boost::filesystem::is_directory(cp))
            directories.insert(boost::filesystem::path(cp.generic_string())); //recreate from generic string to normalize slashes
         else
            files.insert(boost::filesystem::path(cp.generic_string())); //recreate from generic string to normalize slashes
      }
   }
}

boost::filesystem::path source_path_to_dest_path(const boost::filesystem::path& source_root, const boost::filesystem::path& dest_root, const boost::filesystem::path& source_path) {
   boost::filesystem::path dest_path = dest_root / boost::filesystem::relative(source_path, source_root);
   return boost::filesystem::path(dest_path.generic_string());
}

//===


sce_junction::sce_junction(boost::filesystem::path value)
   : m_value(value),
      m_real(std::string())
{
}

sce_junction::sce_junction(const sce_junction& other)
   : m_value(other.m_value),
      m_real(other.m_real)
{

}

//comparison is done as case insensitive
//this is because virtual path in files.db may not exactly match to physical path
//in real world - windows is case insensitive while linux is case sensitive
//it seems that pfs assumes windows as its prior filesystem for tools
bool sce_junction::is_equal(boost::filesystem::path p) const
{
   std::string left = m_value.generic_string();
   boost::to_upper(left);

   std::string right = p.generic_string();
   boost::to_upper(right);

   return left == right;
}

bool sce_junction::is_equal(const sce_junction& other) const
{
   return is_equal(other.m_value);
}

bool sce_junction::operator<(const sce_junction& other)
{
   return m_value < other.m_value;
}

bool sce_junction::operator<(const sce_junction& other) const 
{
   return m_value < other.m_value;
}

void sce_junction::link_to_real(const sce_junction& p) const
{
   m_real = p.m_value;
}

//get size of real file linked with this junction
boost::uintmax_t sce_junction::file_size() const
{
   return boost::filesystem::file_size(m_real);
}

//open real file linked with this junction
bool sce_junction::open(std::ifstream& in) const
{
   if(m_real.generic_string().length() > 0)
   {
      in.open(m_real.generic_string().c_str(), std::ios::in | std::ios::binary);

      if(!in.is_open())
         return false;

      return true;
   }
   else
   {
      return false;
   }
}

//create empty directory in destination root using path from this junction
bool sce_junction::create_empty_directory(boost::filesystem::path source_root, boost::filesystem::path destination_root) const
{
   //construct new path
   boost::filesystem::path new_path = source_path_to_dest_path(source_root, destination_root, m_real);

   //create all directories on the way
   
   boost::filesystem::create_directories(new_path);

   return true;
}

//create empty file in destination root using path from this junction
//leaves stream opened for other operations like write
bool sce_junction::create_empty_file(boost::filesystem::path source_root, boost::filesystem::path destination_root, std::ofstream& outputStream) const
{
   //construct new path
   boost::filesystem::path new_path = source_path_to_dest_path(source_root, destination_root, m_real);
   boost::filesystem::path new_directory = new_path;
   new_directory.remove_filename();

   //create all directories on the way
   
   boost::filesystem::create_directories(new_directory);

   //create new file

   outputStream.open(new_path.generic_string().c_str(), std::ios::out | std::ios::trunc | std::ios::binary);
   if(!outputStream.is_open())
   {
      std::cout << "Failed to open " << new_path.generic_string() << std::endl;
      return false;
   }

   return true;
}

//create empty file in destination root using path from this junction
bool sce_junction::create_empty_file(boost::filesystem::path source_root, boost::filesystem::path destination_root) const
{
   std::ofstream outputStream;
   if(create_empty_file(source_root, destination_root, outputStream))
   {
      outputStream.close();
      return true;
   }
   else
   {
      return false;
   }
}

//copy file in destination root using path from this junction
bool sce_junction::copy_existing_file(boost::filesystem::path source_root, boost::filesystem::path destination_root) const
{
   //construct new path
   boost::filesystem::path new_path = source_path_to_dest_path(source_root, destination_root, m_real);
   boost::filesystem::path new_directory = new_path;
   new_directory.remove_filename();

   //create all directories on the way
   
   boost::filesystem::create_directories(new_directory);

   //copy the file

   if(boost::filesystem::exists(new_path))
      boost::filesystem::remove(new_path);
   
   boost::filesystem::copy(m_real.generic_string(), new_path);

   if(!boost::filesystem::exists(new_path))
   {
      std::cout << "Failed to copy: " << m_real.generic_string() << " to " << new_path.generic_string() << std::endl;
      return false;
   }

   return true;
}


bool sce_junction::copy_existing_file(boost::filesystem::path source_root, boost::filesystem::path destination_root, std::uintmax_t size) const
{
   if (!copy_existing_file(source_root, destination_root))
      return false;

   // trim size
   boost::filesystem::path new_path = source_path_to_dest_path(source_root, destination_root, m_real);
   boost::filesystem::resize_file(new_path, size);

   return true;
}

std::ostream& operator<<(std::ostream& os, const sce_junction& p)
{  
   os << p.m_value.generic_string();  
   return os;  
}