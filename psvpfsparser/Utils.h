#pragma once

#include <cstdint>
#include <vector>
#include <set>

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

int string_to_byte_array(std::string str, int nBytes, unsigned char* dest);

std::string byte_array_to_string(const unsigned char* source, int nBytes);

int print_bytes(const unsigned char* bytes, int length);

//this can be linked only to existing file!
struct sce_junction
{
private:
   boost::filesystem::path m_value; //virtual path in files.db
   mutable boost::filesystem::path m_real; //real path in file system

public:
   sce_junction(boost::filesystem::path value)
      : m_value(value),
        m_real(std::string())
   {
   }

   sce_junction(const sce_junction& other)
      : m_value(other.m_value),
        m_real(other.m_real)
   {

   }

public:
   bool is_equal(boost::filesystem::path p) const
   {
      std::string left = m_value.generic_string();
      boost::to_upper(left);

      std::string right = p.generic_string();
      boost::to_upper(right);

      return left == right;
   }

   bool is_equal(const sce_junction& other) const
   {
      return is_equal(other.m_value);
   }

public:
   bool operator<(const sce_junction& other)
   {
      return m_value < other.m_value;
   }

   bool operator<(const sce_junction& other) const 
   {
      return m_value < other.m_value;
   }

public:
   void link_to_real(const sce_junction& p) const
   {
      m_real = p.m_value;
   }

public:
   //get size of real file linked with this junction
   boost::uintmax_t file_size() const
   {
      return boost::filesystem::file_size(m_real);
   }

   //open real file linked with this junction
   bool open(std::ifstream& in) const
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
   bool create_empty_directory(boost::filesystem::path source_root, boost::filesystem::path destination_root) const
   {
      //construct new path
      std::string old_root = source_root.generic_string();
      std::string new_root = destination_root.generic_string();
      std::string old_path = m_real.generic_string();
      boost::replace_all(old_path, old_root, new_root);
      boost::filesystem::path new_path(old_path);

      //create all directories on the way
   
      boost::filesystem::create_directories(new_path);

      return true;
   }

   //create empty file in destination root using path from this junction
   //leaves stream opened for other operations like write
   bool create_empty_file(boost::filesystem::path source_root, boost::filesystem::path destination_root, std::ofstream& outputStream) const
   {
      //construct new path
      std::string old_root = source_root.generic_string();
      std::string new_root = destination_root.generic_string();
      std::string old_path = m_real.generic_string();
      boost::replace_all(old_path, old_root, new_root);
      boost::filesystem::path new_path(old_path);
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
   bool create_empty_file(boost::filesystem::path source_root, boost::filesystem::path destination_root) const
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
   bool copy_existing_file(boost::filesystem::path source_root, boost::filesystem::path destination_root) const
   {
      //construct new path
      std::string old_root = source_root.generic_string();
      std::string new_root = destination_root.generic_string();
      std::string old_path = m_real.generic_string();
      boost::replace_all(old_path, old_root, new_root);
      boost::filesystem::path new_path(old_path);
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

public:
   //this operator should only be used for printing to console!
   friend std::ostream& operator<<(std::ostream& os, const sce_junction& p);  
};


void getFileListNoPfs(boost::filesystem::path root_path, std::set<boost::filesystem::path>& files, std::set<boost::filesystem::path>& directories);