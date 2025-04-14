/**
 * @name Use of eval
 * @description Detects use of Python's eval() function which can lead to code execution.
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import python

from FunctionCall fc
where fc.getTarget().getName() = "eval"
select fc, "Avoid using eval() as it can lead to code execution vulnerabilities."
