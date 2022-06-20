#define _CRT_SECURE_NO_WARNINGS
#include "stdio.h"
#include "stdlib.h"

int RESPONSE_SIZE = 0;

char* input_tlv_response(int* response_size) {

	int current_index = 0;
	int current_size = 1;

	char* current_response = malloc(current_size);
	char current_symbol = getchar();

	while (current_symbol != '\n') {

		current_response[current_index] = current_symbol;
		++current_index;

		if (current_index >= current_size) {

			current_size *= 2;
			current_response = realloc(current_response, sizeof(char) * current_size);
		}

		current_symbol = getchar();
	}

	current_response[current_index] = '\0';
	*response_size = current_index + 1;

	return current_response;
}

int tag_bf0c_search(const char* tlv_response, const int* tlv_size) {

	int bf0c_tag_end = -1;
	int factor = 0;

	int bf0c_tag_factor = 1;
	
	for (int i = 0; i < *tlv_size - 3 && bf0c_tag_factor; ++i) {

		if ((tlv_response[i] == 'B' || tlv_response[i] == 'b') && 
			(tlv_response[i + 1] == 'F' || tlv_response[i + 1] == 'f') &&
			tlv_response[i + 2] == '0' && (tlv_response[i + 3] == 'C' || tlv_response[i + 3] == 'c')) {

			bf0c_tag_factor = 0;
			factor = 1;

			printf("\n \nTag BF0C: File Control Information(FCI) Discretionary Data");
			printf("\nLength: %c%c", tlv_response[i + 4], tlv_response[i + 5]);
			printf("%s", "\nValue: ");

			for (int j = i + 6; j < *tlv_size; ++j) {
				printf("%c", tlv_response[j]);
			}

			bf0c_tag_end = i + 6;
		}
	}
	
	if (!factor) {

		printf("\n \nTag BF0C: NOT FOUND!");
	}
	
	return bf0c_tag_end;
}

int from_hex_to_decimal(const char* hex) {

	int decimal_number = 0;

	char hex_char_1 = hex[0];
	char hex_char_2 = hex[1];

	if (hex_char_1 >= '0' && hex_char_1 <= '9' && hex_char_2 >= '0' && hex_char_2 <= '9') {
		decimal_number = 16 * (hex_char_1 - '0') + (hex_char_2 - '0');
	}
	else if (hex_char_1 == '0' && (hex_char_2 >= 'a' && hex_char_2 <= 'f') || (hex_char_2 >= 'A' && hex_char_2 <= 'F')) {

		if (hex_char_2 == 'a' || hex_char_2 == 'A') {

			decimal_number = 10;
		}
		else if (hex_char_2 == 'b' || hex_char_2 == 'B') {

			decimal_number = 11;
		}
		else if (hex_char_2 == 'c' || hex_char_2 == 'C') {

			decimal_number = 12;
		}
		else if (hex_char_2 == 'd' || hex_char_2 == 'D') {

			decimal_number = 13;
		}
		else if (hex_char_2 == 'e' || hex_char_2 == 'E') {

			decimal_number = 14;
		}
		else if (hex_char_2 == 'f' || hex_char_2 == 'F') {

			decimal_number = 15;
		}
	}
	
	return decimal_number;
}

int tag_4f_check(const char* tlv_response, const int* count_of_step, const int* tag_61_end) {

	int factor = 0;
	int tag_4f_factor = 1;

	const int RID_SIZE = 11;
	const int HEX_SIZE = 2;
	char* hex_number = malloc(HEX_SIZE);

	const char RID[] = { 'a', 'A', '0', '0', '0', '0', '0', '0','6', '5', '8' };
	for (int i = *tag_61_end; i < *count_of_step - 1 && !factor; ++i) {

		if (tlv_response[i] == '4' && (tlv_response[i + 1] == 'f' || tlv_response[i + 1] == 'F')) {

			factor = 1;
			hex_number[0] = tlv_response[i + 2];
			hex_number[1] = tlv_response[i + 3];

			int tag_4f_length = from_hex_to_decimal(hex_number);
			int rid_index = 0;

			for (int k = i + 4; k < i + 2 * tag_4f_length + 4 && tag_4f_factor && rid_index < RID_SIZE; ++k) {

				if (!rid_index) {

					tag_4f_factor = (tlv_response[k] == RID[rid_index] || tlv_response[k] == RID[rid_index + 1]) ? 1 : 0;
					rid_index += 2;
				}
				else {

					tag_4f_factor = (tlv_response[k] == RID[rid_index]) ? 1 : 0;
					rid_index += 1;
				}
			}

			printf("\n \t \tTag 4F: Application Identifier");
			printf("\n \t \tLength: %c%c", hex_number[0], hex_number[1]);
			printf("\n \t \tValue: ");

			for (int j = i + 4; j < i + 2 * tag_4f_length + 4; ++j) {
				printf("%c", tlv_response[j]);
			}
		}
	}

	if (!factor) {
		return 0;
	}

	free(hex_number);

	return tag_4f_factor;
}

int tag_61_search(const char* tlv_response, const int* tlv_size, const int* tag_bf0c_end) {

	if (*tag_bf0c_end == -1) {

		printf("\n \nTag BF0C: ERROR!");
		return 0;
	}

	int index = *tag_bf0c_end;

	const int HEX_SIZE = 2;
	char* hex_number = malloc(HEX_SIZE);

	int step = 0;
	int list_count = 0;

	while(index < *tlv_size - 3) {

		if (tlv_response[index] == '6' && tlv_response[index + 1] == '1') {

			hex_number[0] = tlv_response[index + 2];
			hex_number[1] = tlv_response[index + 3];

			printf("\n \tTag 61: Application Template");
			printf("\n \tLength: %c%c", hex_number[0], hex_number[1]);
			printf("\n \tValue: ");

			step = from_hex_to_decimal(hex_number);

			int tag_61_end = index + 4;
			int count_of_steps = index + 2 * step + 4;

			for (int i = tag_61_end; i < count_of_steps; ++i) {
				
				printf("%c", tlv_response[i]);
			}

			int tag_4f_factor = tag_4f_check(tlv_response, &count_of_steps, &tag_61_end);

			if (tag_4f_factor) {
				++list_count;
			}

			index += step;
		}
		else {
			++index;
		}
	}

	free(hex_number);

	return list_count;
}

int* rid_pix_list_values(const char* tlv_response, const int* tlv_size, const int* list_size, const int* tag_bf0c_end) {

	if (!(*list_size)) {

		int* null = NULL;
		printf("\n \nit is impossible to form RID+PIX - LIST: RID+PIX - LIST has 0 length!");
		return null;
	}

	const int HEX_SIZE = 2;

	int triple_size = (*list_size) * 3;
	int* triple = malloc(sizeof(int) * triple_size);
	char* hex_number = malloc(HEX_SIZE);

	int current_index = 0;
	int index = *tag_bf0c_end;

	const int RID_SIZE = 11;
	const char RID[] = { 'a', 'A', '0', '0', '0', '0', '0', '0','6', '5', '8' };

	while(index < *tlv_size - 1) {

		if (tlv_response[index] == '6' && tlv_response[index + 1] == '1') {

			hex_number[0] = tlv_response[index + 2];
			hex_number[1] = tlv_response[index + 3];

			int step = from_hex_to_decimal(hex_number);

			int tag_87_factor = 1;
			int tag_87_priority = 0;
			
			for (int i = index + 4; i < index + step * 2 + 4 && tag_87_factor; ++i) {

				if (tlv_response[i] == '8' && tlv_response[i + 1] == '7') {

					tag_87_factor = 0;

					hex_number[0] = '0';
					hex_number[1] = tlv_response[i + 5];

					tag_87_priority = from_hex_to_decimal(hex_number);
				}
			}

			int tag_4f_factor = 1;
			int tag_4f_length;
			int result_index;
			int factor = 1;

			for (int i = index + 4; i < index + step * 2 + 4 && tag_4f_factor; ++i) {

				if (tlv_response[i] == '4' && (tlv_response[i + 1] == 'f' || tlv_response[i + 1] == 'F')) {

					tag_4f_factor = 0;

					hex_number[0] = tlv_response[i + 2];
					hex_number[1] = tlv_response[i + 3];

					tag_4f_length = from_hex_to_decimal(hex_number);
					int rid_index = 0;
					
					for (int k = i + 4; k < i + 2 * tag_4f_length + 4 && factor && rid_index < RID_SIZE; ++k) {

						if (!rid_index) {

							factor = (tlv_response[k] == RID[rid_index] || tlv_response[k] == RID[rid_index + 1]) ? 1 : 0;
							rid_index += 2;
						}
						else {

							factor = (tlv_response[k] == RID[rid_index]) ? 1 : 0;
							rid_index += 1;
						}
					}

					result_index = i + 4;
				}
			}

			if (factor) {

				triple[current_index] = tag_87_priority;
				triple[current_index + 1] = result_index;
				triple[current_index + 2] = tag_4f_length;

				current_index += 3;
			}

			index += step;
		}
		else {
			++index;
		}
	}

	free(hex_number);

	return triple;
}

void form_rid_pix_list(const char* tlv_response, int* rid_pix, const int* size) {

	const int LEN = 3;

	if (*size == LEN) {

		printf("\n \n######################## RESULT ########################\n \n");
		for (int i = rid_pix[1]; i < rid_pix[1] + rid_pix[2] * 2; ++i) {

			printf("%c", tlv_response[i]);
		}

		return;
	}

	printf("\n \n######################## RESULT ########################\n \n");

	int count_null_priority = 0;
	int index = 0;

	while (index < *size) {
		
		if (!rid_pix[index]) {
			++count_null_priority;
		}

		index += LEN;
	}

	int new_size = *size / LEN;

	if (!count_null_priority) {
	
		for (int i = 0; i < new_size; ++i) {

			int min_index = i * LEN;
			
			for (int j = i + 1; j < new_size; ++j) {

				if (rid_pix[j * LEN] < rid_pix[min_index]) {

					min_index = j * LEN;
				}
			}

			int temp = rid_pix[min_index];
			rid_pix[min_index] = rid_pix[i * LEN];
			rid_pix[i * LEN] = temp;

			int temp_1 = rid_pix[min_index + 1];
			rid_pix[min_index + 1] = rid_pix[i * LEN + 1];
			rid_pix[i * LEN + 1] = temp_1;

			int temp_2 = rid_pix[min_index + 2];
			rid_pix[min_index + 2] = rid_pix[i * LEN + 2];
			rid_pix[i * LEN + 2] = temp_2;
		}

		for (int i = 0; i < *size; i += 3) {

			int current_size = rid_pix[i + 1] + (2 * rid_pix[i + 2]);

			for (int j = rid_pix[i + 1]; j < current_size; ++j) {

				printf("%c", tlv_response[j]);
			}

			printf("%c", '\n');
		}

		return;
	}
	else if (count_null_priority) {

		int null_priority_size = count_null_priority * LEN;
		int* null_priority = malloc(sizeof(int) * null_priority_size);

		int not_null_priority_size = (*size - count_null_priority * LEN);
		int* not_null_priority = malloc(sizeof(int) * not_null_priority_size);

		int index_1 = 0;
		int index_2 = 0;

		for (int i = 0; i < new_size; ++i) {

			if (!rid_pix[i * LEN]) {

				int current_index = 0;
				for (int j = index_1; j < index_1 + LEN; ++j) {

					null_priority[j] = rid_pix[i * LEN + current_index];
					++current_index;
				}

				index_1 += 3;
			}
			else {

				int current_index = 0;
				for (int j = index_2; j < index_2 + LEN; ++j) {

					not_null_priority[j] = rid_pix[i * LEN + current_index];
					++current_index;
				}

				index_2 += 3;
			}
		}

		for (int i = 0; i < not_null_priority_size / 3 - 1; ++i) {

			int min_index = i * LEN;

			for (int j = i + 1; j < not_null_priority_size / 3; ++j) {

				if (not_null_priority[j * LEN] < not_null_priority[min_index]) {

					min_index = j * LEN;
				}
			}

			int temp = not_null_priority[min_index];
			not_null_priority[min_index] = not_null_priority[i * LEN];
			not_null_priority[i * LEN] = temp;

			int temp_1 = not_null_priority[min_index + 1];
			not_null_priority[min_index + 1] = not_null_priority[i * LEN + 1];
			not_null_priority[i * LEN + 1] = temp_1;

			int temp_2 = not_null_priority[min_index + 2];
			not_null_priority[min_index + 2] = not_null_priority[i * LEN + 2];
			not_null_priority[i * LEN + 2] = temp_2;
		}

		for (int i = 0; i < not_null_priority_size; i += 3) {

			int current_size = not_null_priority[i + 1] + (2 * not_null_priority[i + 2]);

			for (int j = not_null_priority[i + 1]; j < current_size; ++j) {

				printf("%c", tlv_response[j]);
			}

			printf("%c", '\n');
		}

		for (int i = 0; i < null_priority_size; i += 3) {

			int current_size = null_priority[i + 1] + (2 * null_priority[i + 2]);

			for (int j = null_priority[i + 1]; j < current_size; ++j) {

				printf("%c", tlv_response[j]);
			}

			printf("%c", '\n');
		}

		free(null_priority);
		free(not_null_priority);
	}
}

int main() {

	char* response = input_tlv_response(&RESPONSE_SIZE);

	int bf0c_index = tag_bf0c_search(response, &RESPONSE_SIZE);

	int n = tag_61_search(response, &RESPONSE_SIZE, &bf0c_index);
	
	n = n * 3;

	int* numbers = rid_pix_list_values(response, &RESPONSE_SIZE, &n, &bf0c_index);
	form_rid_pix_list(response, numbers, &n);

	free(numbers);
	free(response);

	return 0;
}