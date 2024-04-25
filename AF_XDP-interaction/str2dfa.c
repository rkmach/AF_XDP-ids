#include <stdio.h>
#include <Python.h>
#include "str2dfa.h"
#include <stdio.h>
#include <string.h>

void py_initialize(){
	Py_Initialize();
}

void py_finalize(){
	Py_Finalize();
}

int str2dfa(char **pattern_list, int pattern_list_len, struct dfa_struct *result) {
	PyObject *pName, *pModule, *pFunc, *pArgs, *pReturn;
	int i_pattern, i_entry, n_entry;

	wchar_t **wargv;
    wargv = (wchar_t**)malloc(1*sizeof(wchar_t *));
    *wargv = (wchar_t*)malloc(6*sizeof(wchar_t));
    **wargv = L'argv1';

	Py_Initialize();
	PySys_SetArgv(1, (wchar_t**)wargv);
	// PySys_SetArgv(1, argv);
	PyRun_SimpleString("import sys\n");
	PyRun_SimpleString("sys.path.append('common')\n");


	pName = PyUnicode_FromString("str2dfa");
	/* Error checking of pName left out */

	pModule = PyImport_Import(pName);
	Py_DECREF(pName);

	if (pModule != NULL) {
		pFunc = PyObject_GetAttrString(pModule, "str2dfa");
		/* pFunc is a new reference */

		if (pFunc && PyCallable_Check(pFunc)) {
			pArgs = PyTuple_New(1);
			PyObject *pPatternList, *pPattern;
			pPatternList = PyList_New(0);
			if (!pPatternList) {
				Py_DECREF(pArgs);
				Py_DECREF(pModule);
				fprintf(stderr, "Cannot convert argument\n");
				return -1;
			}
			for (i_pattern = 0; i_pattern < pattern_list_len; i_pattern++) {
				pPattern = PyUnicode_FromString(pattern_list[i_pattern]);
				if (!pPattern) {
					Py_DECREF(pArgs);
					Py_DECREF(pModule);
					fprintf(stderr, "Cannot convert argument\n");
					return -1;
				}
				PyList_Insert(pPatternList, i_pattern, pPattern);
			}
			PyTuple_SetItem(pArgs, 0, pPatternList);
			pReturn = PyObject_CallObject(pFunc, pArgs);
			Py_DECREF(pArgs);
			if (pReturn != NULL) {
				PyObject *pKey, *pValue, *pEntry;
				n_entry = PyList_Size(pReturn);
				struct dfa_entry *entries = (struct dfa_entry *)malloc(sizeof(struct dfa_entry) * n_entry);
				for (i_entry = 0; i_entry < n_entry; i_entry++) {
					pEntry = PyList_GetItem(pReturn, i_entry);
					pKey = PyTuple_GetItem(pEntry, 0);
					pValue = PyTuple_GetItem(pEntry, 1);
					entries[i_entry].key_state =
						PyLong_AsLong(PyTuple_GetItem(pKey, 0));
					entries[i_entry].key_unit =
						(PyBytes_AsString(PyTuple_GetItem(pKey, 1)))[0];
					entries[i_entry].value_state =
						PyLong_AsLong(PyTuple_GetItem(pValue, 0));
					entries[i_entry].value_flag =
						PyLong_AsLong(PyTuple_GetItem(pValue, 1));
				}
				result->entry_number = n_entry;
				result->entries = entries;
				Py_DECREF(pKey);
				Py_DECREF(pValue);
				Py_DECREF(pEntry);
			}
			else {
				Py_DECREF(pFunc);
				Py_DECREF(pModule);
				PyErr_Print();
				fprintf(stderr,"Call failed\n");
				return -1;
			}
		}
		else {
			if (PyErr_Occurred())
				PyErr_Print();
				fprintf(stderr, "Cannot find function \"str2dfa\"\n");
		}
	}
	else {
		PyErr_Print();
		fprintf(stderr, "Failed to load \"str2dfa\"\n");
		return -1;
	}
	Py_Finalize();
	return 0;
}

// essa função recebe o automato recém alocado e o arquivo de padrões. Inicia os campos entries e entry_number do dfa
int
str2dfa_fromfile(const char *pattern_file, struct dfa_struct *result) {
	PyObject *pName, *pModule, *pFunc, *pArgs, *pReturn;
	int i_pattern, i_entry, n_entry;

	wchar_t **wargv;
    wargv = (wchar_t**)malloc(1*sizeof(wchar_t *));
    *wargv = (wchar_t*)malloc(6*sizeof(wchar_t));
    **wargv = L'argv1';

    Py_Initialize();
    PySys_SetArgv(1, (wchar_t**)wargv);
	// PySys_SetArgv(1, argv);
	PyRun_SimpleString("import sys\n");
	PyRun_SimpleString("sys.path.append('common')\n");

	pName = PyUnicode_FromString("str2dfa");
	/* Error checking of pName left out */

	pModule = PyImport_Import(pName);
	Py_DECREF(pName);

	if (pModule != NULL) {
		pFunc = PyObject_GetAttrString(pModule, "str2dfa");
		/* pFunc is a new reference */

		if (pFunc && PyCallable_Check(pFunc)) {
			pArgs = PyTuple_New(1);
			PyObject *pPatternList;
			pPatternList = PyUnicode_FromString(pattern_file);
			if (!pPatternList) {
				Py_DECREF(pArgs);
				Py_DECREF(pModule);
				fprintf(stderr, "Cannot convert argument\n");
				return -1;
			}
			PyTuple_SetItem(pArgs, 0, pPatternList);
			pReturn = PyObject_CallObject(pFunc, pArgs);
			Py_DECREF(pArgs);
			if (pReturn != NULL) {
				PyObject *pKey, *pValue, *pEntry;
				n_entry = PyList_Size(pReturn);
				struct dfa_entry *entries = (struct dfa_entry *)
					malloc(sizeof(struct dfa_entry) * n_entry);
				for (i_entry = 0; i_entry < n_entry; i_entry++) {
					pEntry = PyList_GetItem(pReturn, i_entry);
					pKey = PyTuple_GetItem(pEntry, 0);
					pValue = PyTuple_GetItem(pEntry, 1);
					entries[i_entry].key_state =
						PyLong_AsLong(PyTuple_GetItem(pKey, 0));
					entries[i_entry].key_unit =
						(PyBytes_AsString(PyTuple_GetItem(pKey, 1)))[0];
					entries[i_entry].value_state =
						PyLong_AsLong(PyTuple_GetItem(pValue, 0));
					entries[i_entry].value_flag =
						PyLong_AsLong(PyTuple_GetItem(pValue, 1));
				}
				result->entry_number = n_entry;
				result->entries = entries;
				Py_DECREF(pKey);
				Py_DECREF(pValue);
				Py_DECREF(pEntry);
			}
			else {
				Py_DECREF(pFunc);
				Py_DECREF(pModule);
				PyErr_Print();
				fprintf(stderr,"Call failed\n");
				return -1;
			}
		}
		else {
			if (PyErr_Occurred())
				PyErr_Print();
				fprintf(stderr, "Cannot find function \"str2dfa\"\n");
		}
	}
	else {
		PyErr_Print();
		fprintf(stderr, "Failed to load \"str2dfa\"\n");
		return -1;
	}
	// Py_Finalize();
	return 0;
}
