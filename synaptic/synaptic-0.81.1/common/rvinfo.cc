/*
Defines the constructor
and getter functions for
the RVInfo container class.

TODO: Add function to sort
patches by version order,
function to calculate risk
score.
 */

#include "rvinfo.h"
#include <vector>
#include <string>
#include "rvulnerability.h"
#include "rpatch.h"
#include <stdio.h>
#include <fstream>
#include <iostream>
#include <sstream>

using namespace std;

RVInfo::RVInfo(vector<RVulnerability> vulns, vector<RPatch> patches,
	       vector<string> v_order, string curr_v_text,
	       string patch_v_text, double updated_risk) {
  this->vulns = vulns;
  this->patches = patches;
  this->v_order = v_order;
  this->curr_v_text = curr_v_text;
  this->patch_v_text = patch_v_text;
  this->updated_risk = updated_risk;
}

RVInfo::RVInfo(){
};


int getIndex(vector<string> order, string name){
  for(std::vector<string>::size_type i = 0; i != order.size(); i++){
    if(name.compare(order[i])==0) return i;
  }

  return -1;
}


namespace patchts
{
  template <typename T> std::string to_string(const T& n)
  {
    std::ostringstream stm;
    stm << n;
    return stm.str();
  }
}



std::string RVInfo::getCurrVulnOutput(){
  return curr_v_text;
}

std::string RVInfo::getPatchVulnOutput(){
  return patch_v_text;
}

std::vector<RVulnerability> RVInfo::getVulns() {
  return vulns;
}

std::vector<RPatch> RVInfo::getPatches() {
  return patches;
}

std::vector<string> RVInfo::getOrder(){
  return v_order;
}

string RVInfo::toBePatched(const char *ver){

  
  if(ver == NULL) return "";
  string version = string(ver); 
  string str = "Vulnerabilities Patched by Updating: \n\n";
  int v_index = getIndex(v_order, version);
  if(v_index == -1) return "";
  for(std::vector<RPatch>::size_type i = 0;
      i != patches.size(); i++){
    
    if(getIndex(v_order, patches[i].getVersion()) >= v_index){
       str.append("____________________________\n");
      return str;
    }
    else{
      str.append("Patch: ");
      str.append(patches[i].getVersion());
      str.append("\n");
      str.append("Patch Risk: ");
      str.append(patchts::to_string(patches[i].getRisk()));
      str.append("\n\n");
      vector<RVulnerability> p_vulns = patches[i].getVulns();
      for(std::vector<RVulnerability>::size_type k = 0;
	  k != p_vulns.size(); k++){

	RVulnerability curr = p_vulns[i];
	str.append("\tCVE: ");
	str.append(curr.getCVE());
	str.append("\n");
	str.append("\tDescription: ");
	str.append(curr.getDes());
	str.append("\n");
	str.append("\tRisk: ");
	str.append(patchts::to_string(curr.getRisk()));
	str.append("\n\n");
      }
    }
  }
  str.append("____________________________\n");
  return str;
}

double RVInfo::getCurrRisk(string version) {
  double max = 0;
  int v_index = getIndex(v_order, version);

  for(std::vector<RVulnerability>::size_type i = 0;
      i!=vulns.size(); i++){
    
    RVulnerability curr = vulns[i];
    if(curr.getRisk() > max){
      max = curr.getRisk();
    }   
  }

  for(std::vector<RPatch>::size_type k = 0;
      k!= patches.size(); k++){


    if(getIndex(v_order, patches[k].getVersion()) >= v_index){
      return max;
    }
    else{
      
      if(patches[k].getRisk() > max){

	max = patches[k].getRisk();
      }

      //if we are at the earliest patch, all prior versions
      //must take into account its vulnerabilities, so
      //we consider them.
      if(k == patches.size() - 1){
	
	
	vector<RVulnerability> p_vulns = patches[k].getVulns();
	for(std::vector<RVulnerability>::size_type j = 0;
	    j != p_vulns.size(); j++){

	  if(p_vulns[j].getRisk() > max){

	    max = p_vulns[j].getRisk();
	  }
	}
      }
    }
  }
  return max;
}



double RVInfo::getUpdatedRisk() {

  return updated_risk;
  /*  double max = 0;

  for(std::vector<RVulnerability>::size_type i = 0;
      i != vulns.size(); i++)
  {
    
    if(vulns[i].getRisk() > max) max = vulns[i].getRisk();

  }

  return max;*/
}

