// Copyright 2018-2019 - Omar Sandoval
// SPDX-License-Identifier: GPL-3.0+

#ifndef DRGNPY_H
#define DRGNPY_H

#define PY_SSIZE_T_CLEAN

#include <Python.h>
#include "structmember.h"

#include "docstrings.h"
#include "../drgn.h"
#include "../program.h"

/* These were added in Python 3.7. */
#ifndef Py_UNREACHABLE
#define Py_UNREACHABLE() abort()
#endif
#ifndef Py_RETURN_RICHCOMPARE
#define Py_RETURN_RICHCOMPARE(val1, val2, op)                               \
    do {                                                                    \
        switch (op) {                                                       \
        case Py_EQ: if ((val1) == (val2)) Py_RETURN_TRUE; Py_RETURN_FALSE;  \
        case Py_NE: if ((val1) != (val2)) Py_RETURN_TRUE; Py_RETURN_FALSE;  \
        case Py_LT: if ((val1) < (val2)) Py_RETURN_TRUE; Py_RETURN_FALSE;   \
        case Py_GT: if ((val1) > (val2)) Py_RETURN_TRUE; Py_RETURN_FALSE;   \
        case Py_LE: if ((val1) <= (val2)) Py_RETURN_TRUE; Py_RETURN_FALSE;  \
        case Py_GE: if ((val1) >= (val2)) Py_RETURN_TRUE; Py_RETURN_FALSE;  \
        default:                                                            \
            Py_UNREACHABLE();                                               \
        }                                                                   \
    } while (0)
#endif

#define DRGNPY_PUBLIC __attribute__((visibility("default")))

typedef struct {
	PyObject_HEAD
	struct drgn_object obj;
} DrgnObject;

typedef struct {
	PyObject_VAR_HEAD
	enum drgn_qualifiers qualifiers;
	/*
	 * This serves two purposes: it caches attributes which were previously
	 * converted from a struct drgn_type member, and it keeps a reference to
	 * any objects which are referenced internally by _type. For example, in
	 * order to avoid doing a strdup(), we can set the name of a type
	 * directly to PyUnicode_AsUTF8(s). This is only valid as long as s is
	 * alive, so we store it here.
	 */
	PyObject *attr_cache;
	/*
	 * A Type object can wrap a struct drgn_type created elsewhere, or it
	 * can have an embedded struct drgn_type. In the latter case, type
	 * points to _type.
	 */
	struct drgn_type *type;
	union {
		struct drgn_type _type[0];
		/* An object which must be kept alive for type to be valid. */
		PyObject *parent;
	};
} DrgnType;

typedef struct {
	PyObject_HEAD
	struct drgn_memory_reader reader;
	PyObject *objects;
} MemoryReader;

typedef struct {
	PyObject_HEAD
	DrgnObject *obj;
	uint64_t length, index;
} ObjectIterator;

typedef struct {
	PyObject_HEAD
	struct drgn_program prog;
	PyObject *objects;
	Py_buffer *buffers;
	size_t num_buffers;
	bool inited;
} Program;

typedef struct {
	PyObject_HEAD
	struct drgn_symbol sym;
	DrgnType *type_obj;
} Symbol;

typedef struct {
	PyObject_HEAD
	struct drgn_symbol_index sindex;
	PyObject *objects;
} SymbolIndex;

typedef struct {
	PyObject_HEAD
	struct drgn_type_index tindex;
	PyObject *objects;
} TypeIndex;

extern PyObject *FindObjectFlags_class;
extern PyObject *PrimitiveType_class;
extern PyObject *ProgramFlags_class;
extern PyObject *Qualifiers_class;
extern PyObject *TypeKind_class;
extern PyTypeObject DrgnObject_type;
extern PyTypeObject DrgnType_type;
extern PyTypeObject MemoryReader_type;
extern PyTypeObject ObjectIterator_type;
extern PyTypeObject Program_type;
extern PyTypeObject Symbol_type;
extern PyTypeObject SymbolIndex_type;
extern PyTypeObject TypeIndex_type;
extern PyObject *FaultError;
extern PyObject *FileFormatError;

static inline PyObject *DrgnType_parent(DrgnType *type)
{
	if (type->type == type->_type)
		return (PyObject *)type;
	else
		return type->parent;
}

/* Keep a reference to @p obj in the dictionary @p objects. */
static inline int hold_object(PyObject *objects, PyObject *obj)
{
	PyObject *key;
	int ret;

	if (!objects) {
		PyErr_SetString(PyExc_ValueError, "object is not initialized");
		return -1;
	}

	key = PyLong_FromVoidPtr(obj);
	if (!key)
		return -1;

	ret = PyDict_SetItem(objects, key, obj);
	Py_DECREF(key);
	return ret;
}

static inline int hold_drgn_type(PyObject *objects, DrgnType *type)
{
	PyObject *parent;

	parent = DrgnType_parent(type);
	if (parent && parent != objects)
		return hold_object(objects, parent);
	else
		return 0;
}

int append_string(PyObject *parts, const char *s);
int append_format(PyObject *parts, const char *format, ...);
unsigned long long index_arg(PyObject *obj, const char *msg);
PyObject *byteorder_string(bool little_endian);
int parse_byteorder(const char *s, bool *ret);
int parse_optional_byteorder(PyObject *obj, enum drgn_byte_order *ret);

int add_module_constants(PyObject *m);

bool set_drgn_in_python(void);
void clear_drgn_in_python(void);
struct drgn_error *drgn_error_from_python(void);
PyObject *set_drgn_error(struct drgn_error *err);
void *set_error_type_name(const char *format,
			  struct drgn_qualified_type qualified_type);

static inline DrgnObject *DrgnObject_alloc(Program *prog)
{
	DrgnObject *ret;

	ret = (DrgnObject *)DrgnObject_type.tp_alloc(&DrgnObject_type, 0);
	if (ret) {
		drgn_object_init(&ret->obj, &prog->prog);
		Py_INCREF(prog);
	}
	return ret;
}

int Program_type_arg(Program *prog, PyObject *type_obj, bool can_be_none,
		     struct drgn_qualified_type *ret);
int filename_converter(PyObject *obj, void *result);
int qualifiers_converter(PyObject *arg, void *result);

PyObject *DrgnObject_NULL(PyObject *self, PyObject *args, PyObject *kwds);
DrgnObject *cast(PyObject *self, PyObject *args, PyObject *kwds);
DrgnObject *reinterpret(PyObject *self, PyObject *args, PyObject *kwds);
DrgnObject *DrgnObject_container_of(PyObject *self, PyObject *args,
				    PyObject *kwds);

Program *mock_program(PyObject *self, PyObject *args, PyObject *kwds);
Program *program_from_core_dump(PyObject *self, PyObject *args, PyObject *kwds);
Program *program_from_kernel(PyObject *self, PyObject *args, PyObject *kwds);
Program *program_from_pid(PyObject *self, PyObject *args, PyObject *kwds);
PyObject *DrgnType_wrap(struct drgn_qualified_type qualified_type,
			PyObject *parent);
DrgnType *void_type(PyObject *self, PyObject *args, PyObject *kwds);
DrgnType *int_type(PyObject *self, PyObject *args, PyObject *kwds);
DrgnType *bool_type(PyObject *self, PyObject *args, PyObject *kwds);
DrgnType *float_type(PyObject *self, PyObject *args, PyObject *kwds);
DrgnType *complex_type(PyObject *self, PyObject *args, PyObject *kwds);
DrgnType *struct_type(PyObject *self, PyObject *args, PyObject *kwds);
DrgnType *union_type(PyObject *self, PyObject *args, PyObject *kwds);
DrgnType *enum_type(PyObject *self, PyObject *args, PyObject *kwds);
DrgnType *typedef_type(PyObject *self, PyObject *args, PyObject *kwds);
DrgnType *pointer_type(PyObject *self, PyObject *args, PyObject *kwds);
DrgnType *array_type(PyObject *self, PyObject *args, PyObject *kwds);
DrgnType *function_type(PyObject *self, PyObject *args, PyObject *kwds);

#endif /* DRGNPY_H */