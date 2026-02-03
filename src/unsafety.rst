.. SPDX-License-Identifier: MIT OR Apache-2.0
   SPDX-FileCopyrightText: The Ferrocene Developers

.. default-domain:: spec

.. _fls_jep7p27kaqlp:

Unsafety
========

.. rubric:: Legality Rules

:dp:`fls_r1m7v4k2t9pa`
:dt:`Undefined behavior` is a situation that results in an unbounded error.

:dp:`fls_8kqo952gjhaf`
:dt:`unsafety` is the presence of :t:`[unsafe operation]s` and :t:`[unsafe trait
implementation]s` in program text.

:dp:`fls_9k2m4p7q1v6n`
A :dt:`safety invariant` is an invariant that when violated may result in
:t:`undefined behavior`.

:dp:`fls_M4Q4vAJmapq8`
A :dt:`validity invariant` is an invariant that when violated results in
immediate :t:`undefined behavior`.

:dp:`fls_ovn9czwnwxue`
An :dt:`unsafe operation` is an operation that may result in
:t:`undefined behavior` that is not diagnosed as a static error.

:dp:`fls_pfhmcafsjyf7`
The :t:`[unsafe operation]s` are:

* :dp:`fls_jd1inwz7ulyw`
  Dereferencing a :t:`value` of a :t:`raw pointer type`.

* :dp:`fls_3ra8s1v1vbek`
  Reading or writing an :t:`external static`.

* :dp:`fls_6ipl0xo5qjyl`
  Reading or writing a :t:`mutable static`.

* :dp:`fls_ucghxcnpaq2t`
  Accessing a :t:`field` of a :t:`union`, other than to assign to it.

* :dp:`fls_ljocmnaz2m49`
  Calling an :t:`unsafe function`.

* :dp:`fls_s5nfhBFOk8Bu`
  Calling :t:`macro` :std:`core::arch::asm`.

:dp:`fls_jb6krd90tjmc`
An :dt:`unsafe context` is either an :t:`unsafe block` or an
:t:`unsafe function`.

:dp:`fls_ybnpe7ppq1vh`
An :t:`unsafe operation` shall be used only within an :t:`unsafe context`.

:dp:`fls_uLXIFup49ytu`
:gsee:`unsafe Rust` For :dt:`unsafe Rust`, see :t:`[unsafe operation]s`.
