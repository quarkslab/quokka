@echo off

if not exist "..\third_party" mkdir ..\third_party

curl -o ..\third_party\idasdk74.zip https://idasdk.s3.fr-par.scw.cloud/idasdk74.zip
curl -o ..\third_party\idasdk77.zip https://idasdk.s3.fr-par.scw.cloud/idasdk77.zip
curl -o ..\third_party\idasdk80.zip https://idasdk.s3.fr-par.scw.cloud/idasdk80.zip
curl -o ..\third_party\idasdk81.zip https://idasdk.s3.fr-par.scw.cloud/idasdk81.zip
curl -o ..\third_party\idasdk82.zip https://idasdk.s3.fr-par.scw.cloud/idasdk82.zip
curl -o ..\third_party\idasdk83.zip https://idasdk.s3.fr-par.scw.cloud/idasdk83.zip
curl -o ..\third_party\idasdk84.zip https://idasdk.s3.fr-par.scw.cloud/idasdk84.zip
curl -o ..\third_party\idasdk90sp1.zip https://idasdk.s3.fr-par.scw.cloud/idasdk90sp1.zip

echo Download complete.