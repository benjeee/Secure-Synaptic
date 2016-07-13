#ifndef _JSONPARSER_H_
#define _JSONPARSER_H_

#include <map>
#include <unordered_map>
#include "rvinfo.h"
#include "rvulnerability.h"

extern std::unordered_map<std::string,RVInfo> getMap();
extern string currVulnOutput(vector<RVulnerability> vulns);
extern string patchVulnOutput(vector<RPatch> patches);

#endif 
