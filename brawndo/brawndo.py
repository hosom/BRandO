from __future__ import print_function

import re

from enum import Enum
from ipaddress import ip_address
try:
	from urllib.parse import urlparse
except ImportError:
	from urlparse import urlparse

# Header for a Bro Intel file
_HEADER = '\t'.join([
		'#fields',
		'indicator',
		'indicator_type',
		'meta.source',
		'meta.url',
		'meta.do_notice'
	])

_HASH_PATTERN = re.compile('([a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})')

class IndicatorType(Enum):
	ADDR = 'ADDR'
	URL = 'URL'
	SOFTWARE = 'SOFTWARE'
	EMAIL = 'EMAIL'
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
	'''Type to be used to create individual Bro Intel documents.

	When converted to a string, this document creates a Bro Intel file line.
	'''
	def __init__(self, indicator, indicator_type, source=None, url=None, do_notice=False):

		self.indicator_type = indicator_type
		self.indicator = indicator
		self.source = source
		self.url = url
		self.do_notice = do_notice

	@property
	def indicator(self):
		'''A hash, file name, ip address, etc. for Bro to look for.'''
		return self._indicator
	
	@indicator.setter
	def indicator(self, indicator):

		if type(indicator) is not str:
			raise AttributeError('indicator must be a string')

		# Validate for empty strings
		indicator = indicator.strip()
		if not indicator:
			raise AttributeError('indicator connot be empty')

		# Validate IP Address indicator types
		if self.indicator_type == IndicatorType.ADDR:
			ip = ip_address(indicator)

		# Automatically remove the scheme, since Bro doesn't want that
		if self.indicator_type == IndicatorType.URL:
			url = urlparse(indicator)
			indicator = url.geturl().replace('{0}://'.format(url.scheme), '')

		if (self.indicator_type == IndicatorType.FILE_HASH):
			if not _HASH_PATTERN.match(indicator):
				raise AttributeError('indicator does not appear to be a valid hash')
				
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

def bro_print(documents, fpath=None):
	'''Print a list of deduplicated documents as a Bro Intel file. 

	Note: Any differences in documents will result in them not being
	deduplcated. If deduplication is desired, then all sub fields must
	be the same.

	Args:
		documents (list of Document): The list of documents to be printed as 
		an intel file for Bro to consume.
		fpath (str): The filepath to write the Bro file to. If none is
		passed, then the intel file will be printed to stdout.
	Returns:
		None
	'''
	documents = set(documents)
	print(_HEADER, file=None)
	for document in documents:
		if type(document) == Document:
			print(document, file=None)
