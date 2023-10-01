# Spring Security LTPA2 - Web Reactive Sample

[![Build Status](https://github.com/sephiroth-j/spring-security-ltpa2-reactive-sample/workflows/CI%20build/badge.svg)](https://github.com/sephiroth-j/spring-security-ltpa2-reactive-sample/actions?query=workflow%3A%22CI+build%22) [![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Sample project for Web Reactive with Spring Boot to demonstrate the use of [spring-security-ltpa2](https://github.com/sephiroth-j/spring-security-ltpa2-reactive-sample). It uses [an embedded LDAP](https://docs.spring.io/spring-boot/docs/3.0.x/reference/htmlsingle/#data.nosql.ldap.embedded) as user storage and caches the look-up result with [`@Cacheable`](https://docs.spring.io/spring-boot/docs/3.0.x/reference/htmlsingle/#io.caching).
