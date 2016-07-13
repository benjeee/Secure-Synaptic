/*
Defines constructor and
getters for the RPatch
class.
 */
#include <string>
#include <vector>
#include "rpatch.h"
#include "rvulnerability.h"


using namespace std;

RPatch::RPatch(string version, string prev_version,
	       vector<RVulnerability> vulns, double risk_score) {
  this->version = version;
  this->prev_version = version;
  this->vulns = vulns;
  this->risk_score = risk_score;
}

RPatch::RPatch(){
}

string RPatch::getVersion() {
  return this->version;
}

string RPatch::getPrev() {
  return this->prev_version;
}

vector<RVulnerability> RPatch::getVulns(){
  return this->vulns;
}

double RPatch::getRisk() {
  return this->risk_score;
}

