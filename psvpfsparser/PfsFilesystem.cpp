#include "PfsFilesystem.h"

#include "PfsFile.h"

PfsFilesystem::PfsFilesystem(std::shared_ptr<ICryptoOperations> cryptops, std::shared_ptr<IF00DKeyEncryptor> iF00D, std::ostream& output, 
                 const unsigned char* klicensee, boost::filesystem::path titleIdPath)
   : m_cryptops(cryptops), m_iF00D(iF00D), m_output(output), m_titleIdPath(titleIdPath)
{
   memcpy(m_klicensee, klicensee, 0x10);

   m_filesDbParser = std::unique_ptr<FilesDbParser>(new FilesDbParser(cryptops, iF00D, output, klicensee, titleIdPath));

   m_unicvDbParser = std::unique_ptr<UnicvDbParser>(new UnicvDbParser(titleIdPath, output));

   m_pageMapper = std::unique_ptr<PfsPageMapper>(new PfsPageMapper(cryptops, iF00D, output, klicensee, titleIdPath));
}

std::vector<sce_ng_pfs_file_t>::const_iterator PfsFilesystem::find_file_by_path(const std::vector<sce_ng_pfs_file_t>& files, const sce_junction& p) const
{
   for(std::vector<sce_ng_pfs_file_t>::const_iterator it = files.begin(); it != files.end(); ++it)
   {
      if(it->path().is_equal(p))
         return it; 
   }
   return files.end();
}

int PfsFilesystem::mount()
{
   if(m_filesDbParser->parse() < 0)
      return -1;

   if(m_unicvDbParser->parse() < 0)
      return -1;

   if(m_pageMapper->bruteforce_map(m_filesDbParser, m_unicvDbParser) < 0)
      return -1;
   
   return 0;
}

int PfsFilesystem::decrypt_files(boost::filesystem::path destTitleIdPath) const
{
   const sce_ng_pfs_header_t& ngpfs = m_filesDbParser->get_header();
   const std::vector<sce_ng_pfs_file_t>& files = m_filesDbParser->get_files();
   const std::vector<sce_ng_pfs_dir_t>& dirs = m_filesDbParser->get_dirs();

   const std::unique_ptr<sce_idb_base_t>& unicv = m_unicvDbParser->get_idatabase();

   const std::map<std::uint32_t, sce_junction>& pageMap = m_pageMapper->get_pageMap();
   const std::set<sce_junction>& emptyFiles = m_pageMapper->get_emptyFiles();

   m_output << "Creating directories..." << std::endl;

   for(auto& d : dirs)
   {
      if(!d.path().create_empty_directory(m_titleIdPath, destTitleIdPath))
      {
         m_output << "Failed to create: " << d.path() << std::endl;
         return -1;
      }
      else
      {
         m_output << "Created: " << d.path() << std::endl;
      }
   }

   m_output << "Creating empty files..." << std::endl;

   for(auto& f : emptyFiles)
   {
      auto file = find_file_by_path(files, f);
      if(file == files.end())
      {
         m_output << "Ignored: " << f << std::endl;
      }
      else
      {
         if(!f.create_empty_file(m_titleIdPath, destTitleIdPath))
         {
            m_output << "Failed to create: " << f << std::endl;
            return -1;
         }
         else
         {
            m_output << "Created: " << f << std::endl;
         }
      }
   }

   m_output << "Decrypting files..." << std::endl;

   for(auto& t : unicv->m_tables)
   {
      //skip empty files and directories
      if(t->get_header()->get_numSectors() == 0)
         continue;

      //find filepath by salt (filename for icv.db or page for unicv.db)
      auto map_entry = pageMap.find(t->get_icv_salt());
      if(map_entry == pageMap.end())
      {
         m_output << "failed to find page " << t->get_icv_salt() << " in map" << std::endl;
         return -1;
      }

      //find file in files.db by filepath
      sce_junction filepath = map_entry->second;
      auto file = find_file_by_path(files, filepath);
      if(file == files.end())
      {
         m_output << "failed to find file " << filepath << " in flat file list" << std::endl;
         return -1;
      }

      //directory and unexisting file are unexpected
      if(is_directory(file->file.m_info.header.type) || is_unexisting(file->file.m_info.header.type))
      {
         m_output << "Unexpected file type" << std::endl;
         return -1;
      }
      //copy unencrypted files
      else if(is_unencrypted(file->file.m_info.header.type))
      {
         if(!filepath.copy_existing_file(m_titleIdPath, destTitleIdPath, file->file.m_info.header.size))
         {
            m_output << "Failed to copy: " << filepath << std::endl;
            return -1;
         }
         else
         {
            m_output << "Copied: " << filepath << std::endl;
         }
      }
      //decrypt encrypted files
      else if(is_encrypted(file->file.m_info.header.type))
      {
         PfsFile pfsFile(m_cryptops, m_iF00D, m_output, m_klicensee, m_titleIdPath, *file, filepath, ngpfs, t);

         if(pfsFile.decrypt_file(destTitleIdPath) < 0)
         {
            m_output << "Failed to decrypt: " << filepath << std::endl;
            return -1;
         }
         else
         {
            m_output << "Decrypted: " << filepath << std::endl;
         }
      }
      else
      {
         m_output << "Unexpected file type" << std::endl;
         return -1;
      }
   }   

   return 0;
}