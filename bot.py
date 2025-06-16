import os
from XUI.XUiApiServices import XUIService
import asyncio
from aiogram import Bot, Dispatcher, types, F, flags
from aiogram.filters import CommandStart, Command
from aiogram import Router
import io
from aiogram.types import ReplyKeyboardMarkup, KeyboardButton
from aiogram.utils.chat_action import ChatActionMiddleware
from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton, WebAppInfo
from aiogram.utils.keyboard import InlineKeyboardBuilder
from dotenv import load_dotenv

load_dotenv()
HOST=os.getenv("HOST")
PORT=os.getenv("PORT")
WEB_PATH=os.getenv("WEB_PATH")
USERNAME=os.getenv("USERNAME")
PASSWORD=os.getenv("PASSWORD")

bot = Bot(token=os.getenv('BOT_TOKEN'))

dp = Dispatcher()
router = Router()

service = XUIService(host=HOST, port=PORT, web_base_path=WEB_PATH, username=USERNAME, password=PASSWORD)
service.login()

list_inbounds = service.list_inbounds()
unique_protocols = set(inbound['protocol'] for inbound in list_inbounds)


@dp.message(CommandStart())
async def cmd_start(message: types.Message):
    inline_kb_list = InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text=str(one), callback_data=str(one))] for one in unique_protocols])
    await message.answer('Выберите протокол', reply_markup=inline_kb_list)

@dp.callback_query(F.data == 'wireguard')
async def protocol_wireguard(message: types.Message):
    inbound = service.get_least_clients_inbound('wireguard')
    name = message.from_user.username or message.from_user.first_name or message.from_user.last_name or message.chat.id
    result = service.add_wireguard_peer(inbound['id'], name)
    format_result = service.format_wg_config(result)
    input_file = types.BufferedInputFile(format_result.encode(), filename=f'{name}.conf')
    await bot.send_document(chat_id=message.message.chat.id, document=input_file)


@dp.callback_query(F.data == 'vless')
async def protocol_vless(message: types.Message):
    inbound = service.get_least_clients_inbound('vless')
    name = message.from_user.username or message.from_user.first_name or message.from_user.last_name or message.chat.id
    result = service.add_client(inbound['id'], name)
    format_result = service.format_vless_url(result, inbound, HOST, inbound['port'])
    await bot.send_message(message.message.chat.id, f'`{format_result}`', parse_mode='markdown')


async def main():
    print('Бот запущен...')
    await dp.start_polling(bot)

if __name__ == '__main__':
    asyncio.run(main())
