# encoding: utf-8

# Copyright 2016, Patrick Muench
# Copyright 2016-2019 DevSec Hardening Framework Team
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
require 'net/http'
require 'json'
require 'uri'

title 'Docker Regitry Security Assessment'

# attributes
REGISTRY_SCHEMA = attribute(
  'registry_schema',
  description: 'define the registry schema',
  default: 'http'
)

REGISTRY_HOST = attribute(
  'registry_host',
  description: 'define the registry host address',
  default: 'localhost'
)

REGISTRY_PORT = attribute(
  'registry_port',
  description: 'define the registry port',
  default: '5000'
)

API_VERSION = 'v2'

control 'registry-control-01' do
  impact 1.0
  title 'Verify Docker Registry HTTP is not used or redirected to HTTPS'
  desc 'Verify Docker Registry HTTP is not used or redirected to HTTPS'
  
  describe.one do
	  describe http("http://" + REGISTRY_HOST + ":" + REGISTRY_PORT) do
		its("status") { should_not cmp 200 }
		its("status") { should_not cmp 401 }
	  end
	  
	  describe http("http://" + REGISTRY_HOST + ":" + REGISTRY_PORT, max_redirects: 0) do
		its("status") { should cmp 301 }
	  end
  end
  
end

control 'registry-control-02' do
  impact 1.0
  title 'Verify API version endpoint authentication'
  desc 'Verify API version endpoint authentication'
  
  api_version = REGISTRY_SCHEMA + "://" + REGISTRY_HOST + ":" + REGISTRY_PORT + "/" + API_VERSION + "/"
  describe http(api_version, ssl_verify: true) do
	its("status") { should_not cmp 200 }
	its("status") { should_not cmp 401 }
  end
  
end

control 'registry-control-03' do
  impact 1.0
  title 'Verify repository Catalog endpoint authentication'
  desc 'Verify repository Catalog endpoint authentication'
  
  catalog = REGISTRY_SCHEMA + "://" + REGISTRY_HOST + ":" + REGISTRY_PORT + "/" + API_VERSION + "/_catalog"
  describe http(catalog, ssl_verify: false) do
	its("status") { should_not cmp 200 }
  end
  
end

control 'registry-control-04' do
  impact 1.0
  title 'Verify images blobs download'
  desc 'Verify images blobs download'
  
  registry_base_addr = REGISTRY_SCHEMA + "://" + REGISTRY_HOST + ":" + REGISTRY_PORT
  
  registry_uri = URI.parse(registry_base_addr) 
  registry_http = Net::HTTP.new(registry_uri.host, registry_uri.port)
  
  if (REGISTRY_SCHEMA == 'http')
	registry_http.use_ssl = false
  end
  registry_http.verify_mode = OpenSSL::SSL::VERIFY_NONE
  
  registry_api_base = "/" + API_VERSION
  
  catalog_relative_path = registry_api_base + "/_catalog"
  catalog_response = registry_http.request(Net::HTTP::Get.new(catalog_relative_path))
  
  if catalog_response.code == '200'
  
	repositories = JSON.parse(catalog_response.body)["repositories"]
	repositories.each do |repository|
		
	repository_tags_list_relative_path = registry_api_base + "/" + repository + "/tags/list"
	tags_response = registry_http.request(Net::HTTP::Get.new(repository_tags_list_relative_path))
	
	if tags_response.code == '200'
	
		tags = JSON.parse(tags_response.body)["tags"]
			tags.each do |tag|
				
				repository_tag_manifest_relative_path = registry_api_base + "/" + repository + "/manifests/" + tag
				manifests_response = registry_http.request(Net::HTTP::Get.new(repository_tag_manifest_relative_path))
				
				if manifests_response.code == '200'
					fsLayers = JSON.parse(manifests_response.body)["fsLayers"]
					fsLayers.each do |fsLayer|
						image_blob = fsLayer['blobSum'].split(":")[1]
						repository_blob_url = registry_base_addr + registry_api_base + "/" + repository + "/blobs/sha256:" + image_blob
						
						describe http(repository_blob_url, ssl_verify: false) do
							its("status") { should_not cmp 200 }
						end
					end
				end
			end
		end
		
	end
  end
   
end
