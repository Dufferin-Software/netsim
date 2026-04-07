# TODO.

## Packages.

Create a python package that houses the python client code for engine and controller, then
import that as a dependency to netsim. I.e. move all of the code in lib/policy\_engine into
into multiple python packages.

## Shitty code.

Remove where possible:

  * Screen scraped data from nodes. The first thing to do is to save interface addresses
    in memory in netsim node classes, instead of scraping the output of ip -4 a and so on.
  * Code duplication.
  
Add where possible:

  * Type checking.
  * Can we generate the python api from graphql schema somehow.

