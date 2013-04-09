
desc "Load virus definitions"
task :loadcvd do
  sh "mkdir cvd; true"
  sh "cd cvd && curl -O http://db.local.clamav.net/main.cvd > /dev/null 2>&1"
end