#include "uos/database/risky_urls_database.h"

#include <utility>
#include <vector>
#include <memory>

#include "sql/database.h"
#include "sql/statement.h"
#include "base/base_paths.h"
#include "base/files/file_util.h"
#include "base/path_service.h"
#include "base/hash/md5.h"
#include "base/files/file_path.h"
#include "ui/base/l10n/l10n_util.h"
#include "chrome/grit/generated_resources.h"
#include "chrome/common/chrome_paths.h"

namespace uos {
namespace database {

////////////////////////////////////////////////////////////////////////////////

// The specific operation realization of RiskyUrlsDatabase
class RiskyUrlsDatabaseImpl : public RiskyUrlsDatabase {
 public:
  RiskyUrlsDatabaseImpl() {}
  ~RiskyUrlsDatabaseImpl() {}

  void Init() override;

  std::string CheckUrlAndReturnType(const std::string& cur_url_host_str) override;
private:
  // database
  std::unique_ptr<sql::Database> risky_urls_db_;

  // database path
  base::FilePath db_path_;

  // Note: This should remain the last member so it'll be destroyed and
  // invalidate its weak pointers before any other members are destroyed.
  base::WeakPtrFactory<RiskyUrlsDatabaseImpl> weak_ptr_factory_{this};

  DISALLOW_COPY_AND_ASSIGN(RiskyUrlsDatabaseImpl);
};

void RiskyUrlsDatabaseImpl::Init() {
  risky_urls_db_ = std::make_unique<sql::Database>();
  risky_urls_db_->set_histogram_tag("Risky Urls");

  base::FilePath data_dir;
  if (base::PathService::Get(chrome::DIR_UOS_USR_SHARE_BROWSER, &data_dir)) {
    base::FilePath data_file = base::FilePath(data_dir.Append("/risky_urls.db"));
    if(!risky_urls_db_->Open(data_file)) {
      return ;
    }
  }
}

 std::string RiskyUrlsDatabaseImpl::CheckUrlAndReturnType(const std::string& cur_url_host_str) {
  if(cur_url_host_str.empty()) {
    return std::string();
  }

  sql::Statement smt(
    risky_urls_db_->GetUniqueStatement("SELECT * FROM unsafe_datas WHERE domain=? OR ip=?"));

  if (!smt.is_valid()) {
    return std::string();
  }

  smt.BindString(0, base::MD5String(cur_url_host_str));
  smt.BindString(1, base::MD5String(cur_url_host_str));

  if(!smt.Step() || smt.ColumnInt(3) == 0) {
    return std::string();
  }

  // return smt.ColumnInt(3);

  std::string risky_text;
  switch (smt.ColumnInt(3))
  {
  case 1:
  risky_text = base::UTF16ToUTF8(l10n_util::GetStringUTF16(IDS_MALICIOUS_FILE));
    break;
  case 2:
  risky_text = base::UTF16ToUTF8(l10n_util::GetStringUTF16(IDS_FAKE_ADVERTISMENT));
    break;
  case 3:
  risky_text = base::UTF16ToUTF8(l10n_util::GetStringUTF16(IDS_INFORMATION_FRAUD));
    break;
  case 4:
  risky_text = base::UTF16ToUTF8(l10n_util::GetStringUTF16(IDS_SOCIAL_FRAUD));
    break;
  default:
  risky_text = std::string();
    break;
  }

  return risky_text;
}


RiskyUrlsDatabase::RiskyUrlsDatabase() {}
RiskyUrlsDatabase::~RiskyUrlsDatabase() {}

std::unique_ptr<RiskyUrlsDatabase> RiskyUrlsDatabase::Create() {
  return std::make_unique<RiskyUrlsDatabaseImpl>();
}

}   //  namespace database
}   //  namespace uos