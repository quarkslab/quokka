import ida_expr
import ida_auto
import ida_pro
import ida_kernwin

ida_auto.auto_wait()

vt = ida_expr.idc_value_t()
ida_expr.eval_idc_expr(vt, ida_kernwin.get_screen_ea(), 'Quokka()')

ida_pro.qexit(0)