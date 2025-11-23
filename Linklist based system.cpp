#include <iostream>
using namespace std;
class bakery {
private:
	int item;
	float price;
	string name;
public:
	bakery() : item (0) , price (0.0), name ("")
	{

	}
	void set_data() {
		cout << "enter item number: ";
		cin >> item;
		cout << "enter item price: ";
		cin >> price;
		cout << "enter item name: ";
		cin >> name;
	}
	void get_data() {
		cout << "item number entered is " << item;
		cout << "price entered is " << price;
		cout << "name entered is " << name;
	}
	int get_item() {
		return item;
	}
};
struct link
{
	link* next;
	bakery data;
};
class Queue
{
	link* front;
public:
	
	Queue() {
		front = NULL;
	}
	bool isEmpty() {
		if(front == NULL)
		return true;
		else
		return false;
	}
	void insert() {
		bakery b;
		b.set_data();
		link* newlink = new link;
		newlink->data = b;
		newlink->next = NULL;
		if (front == NULL)
			front = newlink;
		else {
			link* current = front;
			while (current->next != NULL) {
				current = current->next;
			}
			current->next = newlink;
		}
	}
	void remove() {
		if (front == NULL) {
			cout << "Empty";
			return;
		}
		else {
			link* temp = front;
			front = front->next;
			bakery n;
			n=temp->data;
			temp->next = NULL;
			delete temp;
			cout<<"Deleted data is: ";
			n.get_data();
		}
	}
	void display() {
		if (front == NULL) {
			cout << "Queue is empty" << endl;
		}
		else {
			link* current = front;
			while (current != NULL) {
				current->data.get_data();
				current = current->next;
				cout << endl;
			}
		}
	}
};

int main() {
	Queue q;
	int choice;

	do {

		cout << "\n------Queue Operations Menu:-------\n";
		cout << "1. Insert an item into the queue\n";
		cout << "2. Remove an item from the queue\n";
		cout << "3. Display all items in the queue\n";
		cout << "4. Check if the queue is empty\n";
		cout << "0. Exit\n";
		cout << "Enter your choice: ";
		cin >> choice;

		switch (choice) {
		case 1:
			cout << "\nInserting an item into the queue...\n";
			q.insert();
			break;

		case 2:
			cout << "\nRemoving an item from the queue...\n";
				q.remove();
			break;

		case 3:
			cout << "\nDisplaying all items in the queue:\n";
			q.display();
			break;

		case 4:
			if (q.isEmpty()) {
				cout << "The queue is empty.\n";
			}
			else {
				cout << "The queue is not empty.\n";
			}
			break;

		case 0:
			cout << "Exiting the program.\n";
			break;

		default:
			cout << "Invalid choice\n";
		}
	} while (choice != 0);

	return 0;
}