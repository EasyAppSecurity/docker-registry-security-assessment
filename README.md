Docker Registry Security Assessment InSpec profile

## Standalone Usage

1. Install [InSpec](https://github.com/chef/inspec) for the profile execution

2. Clone the repository
```
$ git clone https://github.com/EasyAppSecurity/docker-registry-security-assessment

```
3. Create properties .yml file in docker-registry-security-assessment/attributes folder, where specify Docker Registry settings. 
For example, centos7-test-attributes.yml:
```
registry_schema : http  <-- registry API schema: http or https
registry_host : localhost  <-- registry host name or address
registry_port : 5000  <-- registry port

```
4. Execute the profile:
```
$ inspec exec docker-registry-security-assessment --input-file docker-registry-security-assessment/attributes/centos7-test-attributes.yml --reporter html:/tmp/registry-assessment-inspec.html

``` 
		
## License and Author

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
