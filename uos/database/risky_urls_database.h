#ifndef UOS_DATABASE_RISKY_URLS_DATABASE_H_
#define UOS_DATABASE_RISKY_URLS_DATABASE_H_

#include <string>
#include <memory>

namespace base {
class FilePath;
}

namespace uos {
namespace database {

class RiskyUrlsDatabase {
 public:
  RiskyUrlsDatabase();
  virtual ~RiskyUrlsDatabase();

  // Creates an instance of RiskyUrlsDatabase.
  static std::unique_ptr<RiskyUrlsDatabase> Create();
  
  // Create or open database and insert datas to it. The datas should be encrypt before insert.
  virtual void Init() = 0;

  // virtual void InsertUpdateHostAndType(const std::string& host, const int& type) = 0;

  // Check whether the current url or host is included in the database, 
  // and put it back to the corresponding prompt
  virtual std::string CheckUrlAndReturnType(const std::string& cur_url_host_str) = 0;
};

}  // namespace database
}  // namespace uos

#endif  //UOS_DATABASE_RISKY_URLS_DATABASE_H_