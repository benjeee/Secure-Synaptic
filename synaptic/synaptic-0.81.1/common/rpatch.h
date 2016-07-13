/*
RPatch is a class that
represents a previous
patched version of a package.
Includes the version and
previous version, a list
of vulnerabilities for
that patch, and a risk
score for that patch.
 */

#include <string>
#include <vector>
#include "rvulnerability.h"
#ifndef _RPATCH_H_
#define    _RPATCH_H_


class RPatch
{

  std::string version;
  std::string prev_version;
  std::vector<RVulnerability> vulns;
  double risk_score;

  public:
                RPatch(std::string version, std::string prev_version,
			       std::vector<RVulnerability> vulns, 
			       double risk_score);
		RPatch();
		std::string getVersion();
		std::string getPrev();
		double getRisk();
		std::vector<RVulnerability> getVulns();

};

#endif
