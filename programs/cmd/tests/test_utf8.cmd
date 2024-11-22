@echo off
echo --- Test 1
set ALPHA=α
if %ALPHA:~0,1% == α (echo alpha) else echo not alpha
