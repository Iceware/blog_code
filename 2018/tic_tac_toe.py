import numpy as np
import pandas as pd

BOARD_ROWS = 3
BOARD_COLS = 3
BOARD_SIZE = BOARD_COLS*BOARD_ROWS


def ComputeHash(board):
    board_ = board.flatten().tolist()
    return "".join([str(i) for i in board_])


class Game:
    def __init__(self, row, col):
        self.row_size = row
        self.col_size = col
        # 0 for not end
        # 1 for winer is first player
        # 2 for winer is second player
        # 3 for tie
        self.end = 0
        self.board = np.zeros((self.row_size, self.col_size))
        self.size = self.board.size
        self.mapping = {0: " ", 1: "X", -1: "O"}


    def DrawCharForItem(self, item):
        # 0 for ' '
        # 1 for 'X'
        # -1 for 'O'
        return self.mapping[item]

    def Print(self):
        items = [self.DrawCharForItem(self.board.item(index))
                 for index in range(self.size)]
        board = """
             {} | {} | {}
            -----------
             {} | {} | {}
            -----------
             {} | {} | {}
        """.format(*items)
        print(board)

    def CheckWin(self):
        result = []

        for i in range(self.row_size):
            result.append(np.sum(self.board[i, :]))
        for i in range(self.col_size):
            result.append(np.sum(self.board[:, i]))

        result.append(0)
        result.append(0)
        for i in range(self.col_size):
            for j in range(self.row_size):
                result[-1] += self.board.item((i, j))
                result[-2] += self.board.item((i, self.row_size-1 - j))

        for i in result:
            if i == 3:
                self.end = 1
                return self.end
            if i == -3:
                self.end = 2
                return self.end
        sum = np.sum(np.abs(self.board))
        if sum == self.size:
            self.end = 3
        return self.end

    def End(self):
        return self.end

    def Step(self, order, action):
        if action[0] < 0 or action[0] > self.row_size-1 or action[1] < 0 or action[1] > self.col_size-1:
            print("x or y invalid")
            return True
        if self.board[action[0], action[1]] != 0:
            print("this palce has already been taken")
            return True
        self.board[action[0], action[1]] = order
        self.CheckWin()
        self.Print()
        return False


class Agent:
    def __init__(self, name, exploration_rate=0.33, learning_rate=0.5, discount_factor=0.01):
        self.states = {}
        # states stack
        self.state_order = []
        self.learning_rate = learning_rate
        self.exploration_rate = exploration_rate
        self.discount_factor = discount_factor
        self.name = name

    def GetSerious(self):
        self.exploration_rate=0

    def exploit(self, board):
        state_value = self.states[ComputeHash(board)]
        x, y = np.where(state_value == state_value.max())
        best_choices = [(a, b) for a, b in zip(x, y)]
        return best_choices[np.random.choice(len(best_choices))]

    def explore(self, board):
        x, y = np.where(board == 0)
        vacant = [(a, b) for a, b in zip(x, y)]
        return vacant[np.random.choice(len(vacant))]

    def set_state(self, board, action):
        hash = ComputeHash(board)
        self.state_order.append((hash, action))

    def SelectMove(self, board):
        action = None
        exploration = np.random.random() < self.exploration_rate
        if exploration or hash not in self.states:
            print("%s exploit" % self.name)
            action = self.explore(board)
        else:
            print("%s exploit" % self.name)
            action = self.exploit(board)
        # update state
        self.set_state(board, action)
        return action

    def learn_by_temporal_difference(self, reward, new_state_hash, state_hash):
        prev_state = self.states.get(
            state_hash, np.zeros((BOARD_ROWS, BOARD_COLS)))
        return self.learning_rate*((reward*self.states[new_state_hash] )- prev_state)

    def OnReward(self, reward):
        hash, action = self.state_order.pop()
        if hash not in self.states:
            self.states[hash] = np.zeros((BOARD_ROWS, BOARD_COLS))
        self.states[hash].itemset(action,reward)

        while self.state_order:
            hash_prev, action_prev = self.state_order.pop()
            reward *= self.discount_factor

            if hash_prev in self.states:
                reward += self.learn_by_temporal_difference(reward, hash, hash_prev).item(action)
                self.states[hash_prev].itemset(action, reward)
            else:    
                self.states[hash_prev] = np.zeros((BOARD_ROWS, BOARD_COLS))
                reward = self.learn_by_temporal_difference(reward, hash, hash_prev).item(action)
                self.states[hash_prev].itemset(action,reward)

            hash = hash_prev
            action = action_prev

        
class HunmanPlayer:
    def SelectMove(self,board):
        action_string = input("Your turn(enter x,y):")
        action_array = action_string.split(",")
        action = (int(action_array[0]),int(action_array[1]))
        return action


def Train(round, bot1, bot2):
    win_trace = pd.DataFrame(data=np.zeros(
        (round, 2)), columns=["bot1", "bot2"])
    for i in range(round):
        print("-"*100)
        print("Round:{}".format(i+1))
        game = Game(BOARD_ROWS, BOARD_COLS)
        turn = 1
        while game.End() == 0:
            if turn == 1:
                action = bot1.SelectMove(game.board)
                game.Step(1, action)
                turn = 2
            else:
                action = bot2.SelectMove(game.board)
                game.Step(-1, action)
                turn = 1

        if game.End() == 1:
            bot1.OnReward(1)
            bot2.OnReward(-1)
            win_trace.set_value(i, 'bot1', 1)
        elif game.End() == 2:
            bot1.OnReward(-1)
            bot2.OnReward(1)
            win_trace.set_value(i, 'bot2', 1)
    return win_trace

def Play(rounds,bot,human):
    for i in range(rounds):
        game = Game(3,3)
        turn = np.random.choice([True, False])
        first = None
        if turn:
            print("Bot first!")
            first = "Bot"
        else:
            print("You first!")
            first = "You"
        while game.End()==0:
            if turn:
                action = bot.SelectMove(game.board)
                while game.Step(1, action):
                    pass
            else:
                action = human.SelectMove(game.board)
                while game.Step(-1, action):
                    pass
            turn ^=1

        if game.End() == 1:
            print("%s win"%first)
        else:
            print("%s lose"%first)


if __name__ == "__main__":
    bot1 = Agent("bot1")
    bot2 = Agent("bot2")
    Train(5000, bot1, bot2)

    print("#"*100)
    bot1.GetSerious()
    bot2.GetSerious()
    human = HunmanPlayer()
    Play(10,bot1,human)
    Play(10,bot2,human)
