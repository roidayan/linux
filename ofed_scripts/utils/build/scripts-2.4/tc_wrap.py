#!/usr/bin/python

import sys
import os
from optparse import OptionParser
from collections import defaultdict
from subprocess import Popen, PIPE

tctool = 'tc'

skprio2tos = { 0 : 0, 2 : 8, 4 : 24, 6 : 16 }

class up2skprio:
	def __init__(self, intf):
		self.map = []
		self.intf = intf

	def get_tagged(self):
		output = Popen('grep -H "EGRESS" /proc/net/vlan/' + self.intf +
                           "* 2> /dev/null", shell=True, bufsize=4096,
                           stdout=PIPE).stdout
		for line in output:
			param, val=line.strip().split(":", 1)
		   	vlan = param.split('.')[-1]
		   	for item in val.split(":", 1)[1].split():
				skprio, up = item.split(':')
			   	skprio = int(skprio)
			   	str = "%d (vlan %s" % (skprio, vlan)
			   	if skprio2tos.get(skprio):
				   str += " tos: %d" % (skprio2tos[skprio])
			   	str += ")"
			   	self.up2skprio[int(up)].append(str)

	def refresh(self):
		self.up2skprio = defaultdict(list)
		skprio = 0
		for up in self.map:
			s = str(skprio)
			if skprio2tos.get(skprio):
				s += " (tos: %s)" % (str(skprio2tos[skprio]))
			self.up2skprio[int(up)].append(s)
			skprio += 1
		self.get_tagged()

	def __getitem__(self, up):
		return self.up2skprio[up]

	def parse_args(self, new):
		for i, up in enumerate(new):
			_up = int(up)
			if (_up > 8 or _up < 0):
				print "Bad user prio: %s - should be in the range: 0-7" % up
				sys.exit(1)

			self.map[i] = up
		self.refresh()

	def set(self, dummy):
		raise NotImplementedError("Setting skprio<=>up mapping is not implemented yet")

class up2skprio_sysfs(up2skprio):
	def __init__(self, path, intf):
		up2skprio.__init__(self, intf)
		self.path = path

		f = open(self.path, "r")
		self.map = f.read().split()
		f.close()

		self.refresh()


	def set(self, new):
		up2skprio.parse_args(new)

		f = open(self.path, "w")
		f.write(" ".join(self.map).strip())
		f.close()

class up2skprio_mqprio(up2skprio):
	def __init__(self, intf):
		empty=True
		up2skprio.__init__(self, intf)

		q = []
		output = Popen(tctool + " qdisc show dev " + intf, shell=True,
				bufsize=4096, stdout=PIPE).stdout

		for line in output:
			empty=False
			param, val=line.strip().split(":", 1)
			if (param == 'qdisc mq 0'):
				self.map=['0' for x in range(16)]
				break
			elif (param == 'queues'):
				for item in val.split():
					q.append(item.translate(None, '()').split(':'))
			elif (param.startswith("qdisc mqprio")):
				if (line.find("Unknown qdisc") > 0):
					print "WARNING: make sure latest tc tool is in path"

				self.map = val.split("map")[1].split()

		if (empty):
			raise IOError("tc tool returned empty output")

		self.refresh()

	def set(self, new):
		up2skprio.parse_args(new)

		try:
			output = Popen("%s qdisc del dev %s root" % (tctool, self.intf),
					shell=True,
					bufsize=4096, stdout=PIPE, stderr=PIPE).stdout

			output = Popen("%s qdisc add dev %s root mqprio num_tc 8 map %s hw 1 " % (tctool,
					self.intf, " ".join(self.map).strip()),
					shell=True,
					bufsize=4096, stdout=PIPE).stdout
		except:
			print "QoS is not supported via mqprio"
			sys.exit(1)

if __name__ == "__main__":
	parser = OptionParser(usage="%prog -i <interface> [options]", version="%prog 1.0")

	parser.add_option("-u", "--skprio_up", dest="skprio_up",
			help="maps sk_prio to UP. LIST is <=16 comma seperated UP. " +
			"index of element is sk_prio.")

	parser.add_option("-i", "--interface", dest="intf",
			  help="Interface name")

	(options, args) = parser.parse_args()

	if (options.intf == None):
		print "Interface name is required"
		parser.print_usage()

		sys.exit(1)

# try using sysfs - if not exist fallback to tc tool
	skprio2up_path = "/sys/class/net/" + options.intf + "/qos/skprio2up"

	try:
		if (os.path.exists(skprio2up_path)):
			up2skprio = up2skprio_sysfs(skprio2up_path, options.intf)
		else:
			up2skprio = up2skprio_mqprio(options.intf)
	except Exception, e:
		print e
		sys.exit(1)

	if (not options.skprio_up == None):
		up2skprio.set(options.skprio_up.split(","))


	for up in range(8):
		print "UP ", up
		for skprio in up2skprio[int(up)]:
			print "\tskprio: " + skprio
