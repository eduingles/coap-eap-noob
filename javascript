TIMEOUT(100000, log.log("last msg: " + msg + "\n"));

msg="dummy";

while (true) {

WAIT_UNTIL(msg.equals("init") || msg.equals("finish") || msg.startsWith("tick"));
log.log(id+" "+time+" "+msg+" \n");

msg="dummy";

}


TIMEOUT(100000);

while (true) {
  log.log(id + " " + time + " " + msg + "\n");
  YIELD();
}
