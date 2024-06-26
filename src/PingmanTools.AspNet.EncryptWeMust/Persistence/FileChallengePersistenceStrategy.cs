﻿using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace PingmanTools.AspNet.EncryptWeMust.Persistence
{
	public class FileChallengePersistenceStrategy : IChallengePersistenceStrategy
	{
		private readonly string _challengeFilePath;

		public FileChallengePersistenceStrategy(string challengeFilePath)
		{
			_challengeFilePath = challengeFilePath;
		}

		public async Task DeleteAsync(IEnumerable<ChallengeDto> challenges)
		{
			var persistedChallenges = await RetrieveAsync();
			var challengesToPersist = persistedChallenges
				.Where(x => 
					challenges.All(y => y.Token != x.Token))
				.ToList();

			await PersistAsync(challengesToPersist);
		}

		public Task PersistAsync(IEnumerable<ChallengeDto> challenges)
		{
			var json = challenges == null ? null : JsonConvert.SerializeObject(challenges.ToArray());

			var bytes = json == null ? null : Encoding.UTF8.GetBytes(json);

			lock (typeof(FileChallengePersistenceStrategy))
			{
				File.WriteAllBytes(
					GetChallengesStorePath(),
					bytes);
			}

			return Task.CompletedTask;
		}

		public Task<IEnumerable<ChallengeDto>> RetrieveAsync()
		{
			lock (typeof(FileChallengePersistenceStrategy))
			{
				if (!File.Exists(GetChallengesStorePath()))
					return Task.FromResult<IEnumerable<ChallengeDto>>(new List<ChallengeDto>());

				var bytes = File.ReadAllBytes(GetChallengesStorePath());
				var json = Encoding.UTF8.GetString(bytes);
				var challenges = JsonConvert.DeserializeObject<IEnumerable<ChallengeDto>>(json);

				return Task.FromResult(challenges);
			}
		}

		private string GetChallengesStorePath()
		{
			return _challengeFilePath + "_Challenges";
		}
	}
}
