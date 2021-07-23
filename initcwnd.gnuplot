set datafile separator ','

set xlabel 'Beginning of window, offset from when connection started [ms]'
set ylabel 'Packets in window'
set boxwidth 0.5
set term pngcairo
set output "initcwnd.png"
set key noautotitle
set style fill solid
plot "initcwnd.csv" using 2:xtic(1) with histogram, '' using 0:2:(sprintf("%d packets", $2)) with labels offset 0.0,0.5
