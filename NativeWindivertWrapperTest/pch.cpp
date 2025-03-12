// pch.cpp: source file corresponding to the pre-compiled header

#include "pch.h"

extern std::string appPath = ""; // Correct path to the executable
extern std::string workingDir = GetWorkingDirectory(appPath); // Correct working directory for the application

// When you are using pre-compiled headers, this source file is necessary for compilation to succeed.
