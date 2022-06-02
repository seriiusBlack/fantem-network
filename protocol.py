class PacketManager:

	def __init__(self):
		pass
	def gen_packet(self):
		pass
	def del_packet(self):
		pass
	def upd_packet(self):
		pass
	def get_packet(self):
		pass

class Packet:

	def __init__(self):
		self.url = None #ftm://TheMcDougalCorporation.6
		self.headers = {}
		self.message = None
		self.data =  None
		self.signature = None
		self.hash_id = None
		self.unique_id = None
		self.salt = None
		self.pepper = None
		self.rand_num = None
		self.size = None
		
	def setHeader(self, header):
		pass
		
	def setHeaders(self, headers):
		pass
		
	def getHeader(self):
		pass
		
	def getHeaders(self):
		pass
		
	def setMessage(self, msg):
		pass
	
	def getMessage(self):
		pass
		
	def setData(self):
		pass
		
	def getData(self):
		pass

	def set_sig(self):
		pass
		
	def get_sig(self):
		pass
	
	def get_hash(self):
		pass

	def set_hash(self):
		pass
		
	def get_uid(self):
		pass
	
	def set_uid(self):
		pass

	def set_salt(self):
		pass

	def get_salt(self):
		pass

	def set_pepper(self):
		pass

	def get_pepper(self):
		pass

	def set_rand_num(self):
		pass

	def get_rand_num(self):
		pass