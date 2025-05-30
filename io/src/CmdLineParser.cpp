#include "CmdLineParser.hpp"

#include <iostream>

CmdLineParser::CmdLineParser(const int& argc, const char**& argv) {
  for (int i = 0; i < argc; ++i) {
    _options.emplace_back(argv[i]);
  }
}

std::string CmdLineParser::get(const std::string& opt_short,
                               const std::string& opt_long) {
  if (!exists(opt_short, opt_long)) {
    std::cerr << "CmdLineParser: Input option " << opt_short << "/" << opt_long
              << " was not found.\n";
    return std::string("");
  }

  auto it_s = std::find(_options.begin(), _options.end(), opt_short);
  auto it_l = std::find(_options.begin(), _options.end(), opt_long);
  auto it = (it_s != _options.end()) ? it_s : it_l;
  auto itp1 = it + 1;
  if (it != _options.end() && itp1 != _options.end()) {
    return *itp1;
  } else if (itp1 == _options.end()) {
    std::cerr << "CmdLineParser: Input option " << opt_short << "/" << opt_long
              << " was not found, but single valued.\n";
  }
  return std::string("");
}

bool CmdLineParser::exists(const std::string& opt_short,
                           const std::string& opt_long) {
  auto short_exists =
      std::find(_options.begin(), _options.end(), opt_short) != _options.end();
  auto long_exists =
      std::find(_options.begin(), _options.end(), opt_long) != _options.end();
  if (short_exists && long_exists) {
    std::cerr << "CmdLineParser: " << opt_short << " and " << opt_long
              << " cannot both exist.\n";
  }
  return short_exists || long_exists;
}