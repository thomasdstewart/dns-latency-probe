# Get sample domains
curl http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip > top-1m.csv.zip
unzip top-1m.csv.zip
head -100 top-1m.csv | awk -F, '{print $2}' > domains.txt
