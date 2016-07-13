/*
C++ parser for json files. 
Loads and parses the security
bundles json and outputs
a map that matches package 
name to vulnerability info.
Uses RapidJson to parse 
into Document class.
 */

#include <apt-pkg/configuration.h>
#include "rapidjson/reader.h"
#include "rapidjson/document.h"
#include "rvinfo.h"
#include <map>
#include <unordered_map>
#include <iostream>
#include <fstream>
#include <sstream>
#include <stdio.h>
#include <assert.h>
#include <vector>
#include <string>
#include <algorithm>

#include "rvulnerability.h"
#include "rpatch.h"
#include "rvinfo.h"
#include <unistd.h>

#include <curl/curl.h>
#include <ctime>
#include <sys/types.h>
#include <sys/stat.h>
#include "config.h"

using namespace rapidjson;
using namespace std;

vector<string> order;

namespace patch
{
  template <typename T> std::string to_string(const T& n)
  {
    std::ostringstream stm;
    stm << n;
    return stm.str();
  }
}

int indexOf(vector<string> order, string name){
  for(std::vector<string>::size_type i = 0; i != order.size(); i++){
    if(name.compare(order[i])==0) return i;
  }

  return -1;
}

bool patchComp(RPatch i, RPatch j){
  return indexOf(order, i.getVersion()) < indexOf(order, j.getVersion());
}

bool vulnComp(RVulnerability i, RVulnerability j){
  return i.getRisk() > j.getRisk();
}

//TODO: Incorporate risk score
string currVulnOutput(vector<RVulnerability> vulns){

   string str;
   str.append("Current Vulnerabilities: \n");
   for(std::vector<RVulnerability>::size_type i = 0; i != vulns.size(); i++){
     RVulnerability curr = vulns[i];
     str.append("CVE: ");
     str.append(curr.getCVE());
     str.append("\n");
     str.append("Description: ");
     str.append(curr.getDes());
     str.append("\n");
     str.append("Risk: ");
     str.append(patch::to_string(curr.getRisk()));
     str.append("\n");
     str.append("\n");
   }
   str.append("____________________________\n");
   return str;
}

string patchVulnOutput(vector<RPatch> patches){
  string str;
  str.append("Patches:\n");
  for(vector<RPatch>::size_type i = 0; i != patches.size(); i++){
    RPatch curr = patches[i];
    str.append("Version: ");
    str.append(curr.getVersion());
    str.append("\n");
    str.append("Previous Version: ");
    str.append(curr.getPrev());
    str.append("\n");
    str.append("Version Risk: ");
    str.append(patch::to_string(curr.getRisk()));
    str.append("\n");
    str.append("Patch Vulnerabilities: \n");
    str.append("\n");
    vector<RVulnerability> vulns = curr.getVulns();

    for(std::vector<RVulnerability>::size_type j = 0; j != vulns.size(); j++){
	 RVulnerability curr_v = vulns[j];
	 str.append("\tCVE: ");
	 str.append(curr_v.getCVE());
	 str.append("\n");
	 str.append("\tDescription: ");
	 str.append(curr_v.getDes());
	 str.append("\n");
	 str.append("\tRisk: ");
	 str.append(patch::to_string(curr_v.getRisk()));
	 str.append("\n");
	 str.append("\n");
    }
  }
  return str;
}

#define MINIMAL_PROGRESS_FUNCTIONALITY_INTERVAL     3
 
struct myprogress {
  double lastruntime;
  CURL *curl;
};

void DoProgress( char label[], int step, int total )
{
    //progress width
    const int pwidth = 72;

    //minus label len
    int width = pwidth - strlen( label );
    int pos = ( step * width ) / total ;

    
    int percent = ( step * 100 ) / total;

    fprintf(stderr,"%s[", label );

    //fill progress bar with =
    for ( int i = 0; i < pos; i++ )  fprintf(stderr, "%c", '=' );

    // //fill progress bar with spaces
    fprintf(stderr, "% *c", width - pos + 1, ']' );
    fprintf(stderr, " %3d%%\r", percent );
}
 
/* this is how the CURLOPT_XFERINFOFUNCTION callback works */ 
static int xferinfo(void *p,
                    curl_off_t dltotal, curl_off_t dlnow,
                    curl_off_t ultotal, curl_off_t ulnow)
{
  struct myprogress *myp = (struct myprogress *)p;
  CURL *curl = myp->curl;
  double curtime = 0;
 
  curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &curtime);
 
  /* under certain circumstances it may be desirable for certain functionality
     to only run every N seconds, in order to do this the transaction time can
     be used */
  if((curtime - myp->lastruntime) >= MINIMAL_PROGRESS_FUNCTIONALITY_INTERVAL) {
    myp->lastruntime = curtime;
    fprintf(stderr, "TOTAL TIME: %f \r", curtime);
  }

  int step = (int) dlnow;
  int total = (int) dltotal;

    if (total != 0) {
        DoProgress("Downloading Security Data: ", step, total);
    }
  
  return 0;
}
 
/* for libcurl older than 7.32.0 (CURLOPT_PROGRESSFUNCTION) */ 
static int older_progress(void *p,
                          double dltotal, double dlnow,
                          double ultotal, double ulnow)
{
  return xferinfo(p,
                  (curl_off_t)dltotal,
                  (curl_off_t)dlnow,
                  (curl_off_t)ultotal,
                  (curl_off_t)ulnow);
}

size_t write_data(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    size_t written = fwrite(ptr, size, nmemb, stream);
    return written;
}

/* returns epoch time in GMT */
const time_t get_last_modified(char* filename)
{
    struct stat attrib;
            
    int succ = stat(filename, &attrib);
    if(succ == -1) {
       attrib.st_mtime = 0; //there was an error reading file (maybe didnt exist) so set modified time to earliest possible to ensure json will be donwloaded
       //printf("errored");
    }
    //printf("%s", ctime(&attrib.st_mtime)); 
    //fflush(stdout);
    return attrib.st_mtime;
}

void download_json()
{
    CURL *curl;
    FILE *fp;
    CURLcode res = CURLE_OK;
    struct myprogress prog;
    const char* host_cstr = std::getenv("SECURITYHOST");
    if (host_cstr == NULL)
    {
      perror("Error: Security data host is undefined. Please define host by setting the environement variable SECURITYHOST.\n(ex: export SECURITYHOST=vacancy.cs.umd.edu)");
    }
    const string host = std::string(host_cstr);
    string url = host + "/security_bundles.json";
    char outfilename[FILENAME_MAX] = "/usr/local/share/synaptic/security_bundles.json";
    curl = curl_easy_init();
    const time_t time_last_modified = get_last_modified(outfilename);
    if (curl) {
        prog.lastruntime = 0;
        prog.curl = curl;

        fp = fopen(outfilename, "wb");

        if (fp == NULL)
          perror("Error opening file");

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        /* use gzip */
        curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "gzip");
        /* progress bar */
        curl_easy_setopt(curl, CURLOPT_PROGRESSFUNCTION, older_progress);
        // pass the struct pointer into the progress function
        curl_easy_setopt(curl, CURLOPT_PROGRESSDATA, &prog);
        #if LIBCURL_VERSION_NUM >= 0x072000
            /* xferinfo was introduced in 7.32.0, no earlier libcurl versions will
            compile as they won't have the symbols around.

            If built with a newer libcurl, but running with an older libcurl:
            curl_easy_setopt() will fail in run-time trying to set the new
            callback, making the older callback get used.

            New libcurls will prefer the new callback and instead use that one even
            if both callbacks are set. */ 
            curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, xferinfo);
            /* pass the struct pointer into the xferinfo function, note that this is
            an alias to CURLOPT_PROGRESSDATA */
            curl_easy_setopt(curl, CURLOPT_XFERINFODATA, &prog);
        #endif
        curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
        /* write file */
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
        /* time condition */
        //curl_easy_setopt(curl, CURLOPT_TIMECONDITION, CURL_TIMECOND_IFMODSINCE);
        // time value compares GMT times
        //curl_easy_setopt(curl, CURLOPT_TIMEVALUE, time_last_modified);
        res = curl_easy_perform(curl);

        /* check for errors */ 
        if(res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n",
                curl_easy_strerror(res));
        }
        else {
            fprintf(stderr, "\nSecurity data is up-to-date!\n");
        }
        /* always cleanup */
        curl_easy_cleanup(curl);
        fclose(fp);
    }
}

unordered_map<string,RVInfo> pkgMap;

unordered_map<string,RVInfo> getMap() {
  if(! pkgMap.empty()) {
    return pkgMap;
  }
 
  download_json();

  Document document;
  char cCurrentPath[FILENAME_MAX];
  getcwd(cCurrentPath, sizeof(cCurrentPath)); 
  //printf ("The current working directory is %s", cCurrentPath);

  std::ifstream in("/usr/local/share/synaptic/security_bundles.json", std::ifstream::in);
  std::string contents((std::istreambuf_iterator<char>(in)),
		       std::istreambuf_iterator<char>());

  unordered_map<string, RVInfo> map;

  document.Parse(contents.c_str());
  assert(document.IsObject());  

  for(Value::ConstMemberIterator itr = document.MemberBegin();
      itr != document.MemberEnd(); ++itr)
    {
      int t1count = 0;
      int t2count = 0;
      const char  *pkgName = itr->name.GetString();
      
      //checking if there is at least 1 type1 vulnerability
      if(itr->value.HasMember("vulnerabilities")) t1count++;
      
 
      //checking if there is at least 1 type2 vulnerability
      for(Value::ConstMemberIterator t2_check = itr->value.MemberBegin();
	  t2_check != itr->value.MemberEnd(); ++t2_check)
      {
        if(t2_check->value.IsObject()){
          t2count++;
          break;
        }	  
      }
      

      //if there is at least 1 vulnerability of either type, we make an entry
      if(t1count > 0 || t2count > 0){
	
	vector<string> v_order;
	vector<RVulnerability> currVulns;
	vector<RPatch> patches;

	//Grabbing v_order field
	//have to do a shallow copy of v_order for now, not sure of a better way
	if(itr->value.HasMember("v_order")){
	    const Value& order = itr->value["v_order"];
	    for(SizeType i = 0; i < order.Size() - 1; i++){
	      if(order[i] != NULL){
		v_order.push_back(order[i].GetString());
	      }
	    }
	}
	
	//adding from type1 vulnerabilities field if it exists
	if(t1count > 0){
	  
	  const Value& t1vulns = itr->value["vulnerabilities"];

	  for(SizeType i = 0; i < t1vulns.Size(); i++){
	    const Value& curr = t1vulns[i];
	    string cve = curr["cve"].GetString();
	    string des = curr["description"].GetString();
	    if(curr.HasMember("extra_info")){
		string extra = curr["extra_info"].GetString();
		if(!extra.empty()){
		  des.append("\n");
		  des.append("Extra Info: ");
		  des.append(extra.c_str());
		}
	    }
	    double risk = curr["cvss"].GetDouble();
	    RVulnerability vuln(cve, des, risk);
	    currVulns.push_back(vuln);
	  }
	}
	
	//adding from type2 fields if there are any
	if(t2count > 0){

	  for(Value::ConstMemberIterator t2_itr = itr->value.MemberBegin();
	      t2_itr != itr->value.MemberEnd(); ++t2_itr)
	    {
	      
	      if(t2_itr->value.IsObject()){
		
		string version = t2_itr->name.GetString();
	        string prev_version = t2_itr->value["prev_v"].GetString();
		double patch_risk = t2_itr->value["risk"].GetDouble();
		const Value& a = t2_itr->value["patches"];
		vector<RVulnerability> patchVulns;
		
		for(SizeType i = 0; i < a.Size(); i++){

		  const Value& c = a[i];
		  string cve = c["cve"].GetString();
		  string des = c["description"].GetString();
		  if(c.HasMember("extra_info")){
		    string extra = c["extra_info"].GetString();
		    if(!extra.empty()){
		      des.append("\n");
		      des.append("Extra Info: ");
		      des.append(extra.c_str());
		    }
		  }
		  double risk = c["cvss"].GetDouble();
		  RVulnerability vuln(cve, des, risk);
		  patchVulns.push_back(vuln);
	       
		}
		
		RPatch p(version, prev_version, patchVulns, patch_risk);
		patches.push_back(p);
		
	      }
	    }
	}

	double max = 0;
	for(std::vector<RVulnerability>::size_type q = 0;
	    q != currVulns.size(); q++)
	  {
    
	    if(currVulns[q].getRisk() > max) max = currVulns[q].getRisk();

	  }
	order = v_order;
	//creating RVInfo container for the package, inserting it into the map
	std::sort(patches.begin(), patches.end(), patchComp);
	std::sort(currVulns.begin(), currVulns.end(), vulnComp);
	string curr_v_text = currVulnOutput(currVulns);
	string patch_v_text = patchVulnOutput(patches);
	RVInfo info(currVulns, patches, v_order, curr_v_text, patch_v_text,max);
	string pkgNameString(pkgName);
	map.insert(make_pair(pkgNameString,info));
      }
    }
   pkgMap = map;
   return pkgMap;
}

//std::vector<string> order=NULL;

//TODO: Delete this section after testing
/*
int main(int argc, char* argv[]) {
  
  map<string, RVInfo> map = getMap();

  RVInfo info = map["libv8"];
  
  vector<RVulnerability> vulns  = info.getVulns();
  printf("%s\n", currVulnOutput(vulns).c_str());
  vector<RPatch> patches = info.getPatches();
  printf("%s\n", patchVulnOutput(patches).c_str());
  
  printf("%s\n", info.getCurrVulnOutput().c_str());
  printf("%s\n", info.getPatchVulnOutput().c_str());

  }*/

