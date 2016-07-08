from enum import Enum

class IndicatorType(Enum):
	ADDR = 'ADDR'
	URL = 'URL'
	SOFTWARE = 'SOFTWARE'
	EMAIl = 'EMAIL'
	DOMAIN = 'DOMAIN'
	USER_NAME = 'USER_NAME'
	FILE_HASH = 'FILE_HASH'
	FILE_NAME = 'FILE_NAME'
	CERT_HASH = 'CERT_HASH'
	PUBKEY_HASH = 'PUBKEY_HASH'

	def __str__(self):

		return 'Intel::{0}'.format(self.value)

class DoNotice(Enum):
	T = True
	F = False

	def __str__(self):

		return '{0}'.format(self._name_)

class Document:

	def __init__(self, indicator, indicator_type, source=None, url=None, do_notice=False):

		self.indicator = indicator
		self.indicator_type = indicator_type
		self.source = source
		self.url = url
		self.do_notice = do_noticek

	@property
	def indicator(self):
		return self._indicator
	
	@indicator.setter
	def indicator(self, indicator):
		self._indicator = indicator

	@property
	def indicator_type(self):
		return self._indicator_type
	
	@indicator_type.setter
	def indicator_type(self, i_type):
		if type(i_type) is not IndicatorType:
			i_type = IndicatorType(i_type)
		self._indicator_type = i_type

	@property
	def source(self):
		return self._source
	
	@source.setter
	def source(self, src):
		if src == None:
			src = '-'
		src = src.replace('\t', ' ')
		self._source = src

	@property
	def url(self):
		return self._url

	@url.setter
	def url(self, link):
		if link == None:
			link = '-'
		self._url = link

	@property
	def do_notice(self):
		return self._do_notice
	
	@do_notice.setter
	def do_notice(self, do_notice):
		if do_notice == None:
			do_notice = False

		if type(do_notice) is not DoNotice:
			do_notice = DoNotice(do_notice)
		self._do_notice = do_notice

	def __str__(self):

		fields = [self.indicator,
				str(self.indicator_type),
				self.source,
				self.url,
				str(self.do_notice)]

		return '\t'.join(fields)