/*
RVInfo is a container for all
vulnerability information about
a specific package. Includes a 
list of current vulnerabilities,
a list of RPatches pertaining
to the package, and the order
of the versions for that package
for sorting purposes.
 */

#ifndef _RVINFO_H_
#define    _RVINFO_H_

#include <string>
#include "rvulnerability.h"
#include "rpatch.h"
#include <vector>


class RVInfo {
  
  std::vector<RVulnerability> vulns;
  std::vector<RPatch> patches;  
  std::vector<std::string> v_order;
  std::string curr_v_text;
  std::string patch_v_text;
  double updated_risk;

 public:

  RVInfo(std::vector<RVulnerability> vulns,
	 std::vector<RPatch> patches,
	 std::vector<std::string> v_order,
	 std::string curr_v_text,
	 std::string patch_v_text,
	 double updated_risk);
  RVInfo();

  std::vector<RVulnerability> getVulns();
  std::vector<RPatch> getPatches();
  std::vector<std::string> getOrder();

  std::string getCurrVulnOutput();
  std::string getPatchVulnOutput();
  std::string toBePatched(const char *ver);
  double getCurrRisk(std::string version);
  double getUpdatedRisk();
};

#endif
