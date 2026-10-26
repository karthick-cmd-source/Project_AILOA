from ai.qwen import ask_qwen


print("=" * 50)
print("AILOA - Qwen 3 Test")
print("=" * 50)

question = input("\nAsk Qwen: ")

answer = ask_qwen(question)

print("\nQwen Response:")
print("-" * 50)
print(answer)
print("-" * 50)

