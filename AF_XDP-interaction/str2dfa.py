#!/usr/bin/env python
# coding=utf-8

import sys
import ahocorasick

class DFAMatchEntriesGenerator():
    def __init__(self, pattern_list, stride=1, table_id=0):
        # Init and configure the automaton
        pattern_number = 0
        self.stride = stride
        self.table_id = table_id
        self.pattern_list = pattern_list
        self.automaton = ahocorasick.Automaton(ahocorasick.STORE_LENGTH)
        for pattern in pattern_list:
            self.automaton.add_word(pattern)
        self.automaton.make_automaton()
        # Generate DFA descriptor according to the automaton
        self.dfa = self.generate_dfa(self.automaton.dump())
        self.msdfa = self.generate_multi_stride_dfa(self.dfa, self.stride)
        self.mat_entries = self.generate_mat_entries(self.msdfa)
        self.key_value_entries = self.generate_key_value_entries(self.msdfa)

    def generate_dfa(self, automaton_graph_descriptor):
        nodes = automaton_graph_descriptor[0]
        edges = automaton_graph_descriptor[1]
        failure_links = automaton_graph_descriptor[2]
        converse_dict = {}
        dfa_nodes = {}
        dfa_edges = []
        dfa_failure_links = []
        dfa_next_nodes = {}
        pattern_idx = 0
        for node_id in range(len(nodes)):
            origin_node_id = nodes[node_id][0]
            converse_dict[origin_node_id] = node_id
            accept_flag = nodes[node_id][1]
            if accept_flag == 1:
                pattern_idx += 1
                accept_flag = pattern_idx
            dfa_nodes[node_id] = accept_flag
            dfa_next_nodes[node_id] = []
        for edge in edges:
            start_node_id = converse_dict[edge[0]]
            transfer_char = edge[1]
            end_node_id = converse_dict[edge[2]]
            dfa_edges.append(
                (start_node_id, transfer_char, end_node_id, 1)
            )
            dfa_next_nodes[start_node_id].append(
                (transfer_char, end_node_id)
            )
        for failure_link in failure_links:
            start_node_id = converse_dict[failure_link[0]]
            intermediate_node_id = converse_dict[failure_link[1]]
            dfa_failure_links.append((start_node_id, intermediate_node_id))
            for next_node in dfa_next_nodes[intermediate_node_id]:
                transfer_char = next_node[0]
                end_node_id = next_node[1]
                cover_flag = False
                for origin_next_node in dfa_next_nodes[start_node_id]:
                    existing_transfer_char = origin_next_node[0]
                    cover_flag = True
                    if transfer_char != existing_transfer_char \
                       and ord(b'\xff') != existing_transfer_char:
                        cover_flag = False
                if not cover_flag:
                    dfa_edges.append(
                        (start_node_id, transfer_char, end_node_id, 0)
                    )
        return (dfa_nodes, dfa_edges, dfa_failure_links, dfa_next_nodes)

    def generate_multi_stride_dfa(self, dfa_descriptor, stride):
        dfa_nodes = dfa_descriptor[0]
        dfa_edges = dfa_descriptor[1]
        dfa_failure_links = dfa_descriptor[2]
        dfa_next_nodes = dfa_descriptor[3]
        dfa_next_nodes_extend = {}
        msdfa_nodes = dfa_nodes
        msdfa_edges = []
        msdfa_next_nodes = {}
        for dfa_node_id in dfa_nodes:
            dfa_next_nodes_extend[dfa_node_id] = dfa_next_nodes[dfa_node_id][:]
            msdfa_next_nodes[dfa_node_id] = []
        for (start_node_id, transfer_char, end_node_id, type) in dfa_edges:
            if start_node_id == 0 and type == 1:
                for star_num in range(1, stride):
                    transfer_chars = b'\xff' * star_num + transfer_char
                    dfa_next_nodes_extend[start_node_id].append(
                        (transfer_chars, end_node_id)
                    )
            if dfa_nodes[end_node_id] != 0 and type == 1:
                for star_num in range(1, stride):
                    transfer_chars = transfer_char + b'\xff' * star_num
                    dfa_next_nodes_extend[start_node_id].append(
                        (transfer_chars, end_node_id)
                    )
        for dfa_node in dfa_nodes:
            start_node_id = dfa_node
            self.find_multi_stride_edges(
                msdfa_edges, msdfa_next_nodes, dfa_next_nodes_extend, \
                start_node_id, b'', start_node_id, stride
            )
        for failure_link in dfa_failure_links:
            start_node_id = failure_link[0]
            intermediate_node_id = failure_link[1]
            for next_node in msdfa_next_nodes[intermediate_node_id]:
                transfer_chars = next_node[0]
                end_node_id = next_node[1]
                cover_flag = False
                for origin_next_node in msdfa_next_nodes[start_node_id]:
                    existing_path = origin_next_node[0]
                    cover_flag = True
                    for idx in range(stride):
                        if transfer_chars[idx] != existing_path[idx] \
                           and ord(b'\xff') != existing_path[idx]:
                            cover_flag = False
                            break
                if not cover_flag:
                    msdfa_edges.append(
                        (start_node_id, transfer_chars, end_node_id, 0)
                    )
        return (msdfa_nodes, msdfa_edges)

    def find_multi_stride_edges(self, msdfa_edges, msdfa_next_nodes, \
                                dfa_next_nodes, start_node_id, \
                                current_path, current_node_id, stride):
        for next_node in dfa_next_nodes[current_node_id]:
            next_path = current_path + next_node[0]
            next_node_id = next_node[1]
            if len(next_path) < stride:
                self.find_multi_stride_edges(
                    msdfa_edges, msdfa_next_nodes, dfa_next_nodes, \
                    start_node_id, next_path, next_node_id, stride
                )
            elif len(next_path) == stride:
                transfer_chars = next_path
                end_node_id = next_node_id
                msdfa_edges.append(
                    (start_node_id, transfer_chars, end_node_id, 1)
                )
                msdfa_next_nodes[start_node_id].append(
                    (transfer_chars, end_node_id)
                )
            else:
                continue
    
    def acha_padrao(self, edges, final_state):
        # import pdb; pdb.set_trace()
        type_1_edges = []
        for (current_state, received_chars, next_state, type) in edges:
            if type == 1:
                type_1_edges.append((current_state, received_chars, next_state, type))

        type_1_edges = type_1_edges[::-1]
        padrao = ''
        
        while True:
            for (current_state, received_chars, next_state, type) in type_1_edges:
                if current_state == 0 and next_state == final_state:
                    padrao += received_chars.decode('utf-8')
                    return padrao
                if next_state == final_state:
                    padrao += received_chars.decode('utf-8')
                    final_state = current_state
                    break

    def generate_mat_entries(self, msdfa_descriptor):
        msdfa_nodes = msdfa_descriptor[0]
        msdfa_edges = msdfa_descriptor[1]
        mat_entries = []
        cont = 1
        for (current_state, received_chars, next_state, type) in msdfa_edges:
            match = (current_state, received_chars)
            modifier = 0
            matched_pattern = '~'
            if msdfa_nodes[next_state] != 0:
                modifier = cont
                cont += 1
                matched_pattern = self.acha_padrao(msdfa_edges, next_state)
            action_params = (next_state, modifier, matched_pattern[::-1])
            mat_entries.append((match, action_params))
        return mat_entries

    def generate_key_value_entries(self, msdfa_descriptor):
        msdfa_nodes = msdfa_descriptor[0]
        msdfa_edges = msdfa_descriptor[1]
        key_value_entries = []
        for (current_state, received_chars, next_state, type) in msdfa_edges:
            key = (current_state, received_chars)
            value = (next_state, msdfa_nodes[next_state])
            key_value_entries.append((key, value))
        return key_value_entries

    def get_automaton(self):
        return self.automaton

    def get_dfa(self):
        return self.dfa

    def get_multi_stride_dfa(self):
        return self.msdfa

    def get_mat_entries(self):
        return self.mat_entries

    def get_key_value_entries(self):
        return self.key_value_entries

def str2dfa(pattern_list):
    patterns = []
    if type(pattern_list) == str:
        pattern_file = open(pattern_list, 'r')
        for pattern in pattern_file.readlines():
            patterns.append(pattern[:-1])
    entries_generator = DFAMatchEntriesGenerator(patterns, 1)
    return entries_generator.get_mat_entries()

if __name__ == '__main__':
    x = str2dfa(sys.argv[1])
    for i in x:
        print(f"{i[0][0]},{(i[0][1]).decode('utf-8')},{i[1][0]},{i[1][1]},{i[1][2]}")