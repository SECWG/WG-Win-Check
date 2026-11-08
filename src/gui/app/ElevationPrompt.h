#pragma once

#include <windows.h>

enum class ElevationPromptResult {
    ContinueNormal = 0,
    ExitApplication,
    Relaunched
};

ElevationPromptResult ShowElevationPrompt(HINSTANCE hInstance);
