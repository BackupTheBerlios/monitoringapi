set size square 1,1
set data style linespoint
set grid
set nokey 
set xtics border (0,8,16,32,64,128,256,512,1024)
set xlabel 'Socket receive buffer size (Kbytes)'
set ylabel 'Packets dropped (Ratio)' 
set logscale x

#Packets received 1426641
plot '../measurements/so_rcv_buf.txt' using 1:($2*100/1426641)

pause -1
