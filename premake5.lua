solution "HelloWorld"
   configurations { "Release" }

project "steamlink"
   kind "ConsoleApp"
   language "C++"
   targetdir "bin"

   files { "src/**.h", "src/**.hpp", "src/**.cpp" }

   filter "configurations:Release"
      defines { "NDEBUG" }
      optimize "On"
