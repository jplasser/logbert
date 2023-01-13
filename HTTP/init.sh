file="../output/http"
if [ -e $file ]
then
  echo "$file exists"
else
  mkdir -p $file
fi

file="../output/http/bert"
if [ -e $file ]
then
  echo "$file exists"
else
  mkdir -p $file
fi